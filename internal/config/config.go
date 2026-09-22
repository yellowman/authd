package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const defaultListen = "127.0.0.1:8080"

type Config struct {
	Issuer      string
	Listen      string
	DatabaseURL string
	MasterKey   []byte
	Development bool

	AccessTokenTTL       time.Duration
	AuthorizationCodeTTL time.Duration
	SessionIdleTTL       time.Duration
	SessionAbsoluteTTL   time.Duration
	RefreshIdleTTL       time.Duration
	RefreshAbsoluteTTL   time.Duration
	CleanupInterval      time.Duration
	AuditRetention       time.Duration
	TrustedProxies       []netip.Prefix
}

func Load() (Config, error) {
	cfg := Config{
		Issuer:      strings.TrimSuffix(strings.TrimSpace(os.Getenv("AUTHD_ISSUER")), "/"),
		Listen:      strings.TrimSpace(os.Getenv("AUTHD_LISTEN")),
		DatabaseURL: strings.TrimSpace(os.Getenv("DATABASE_URL")),
	}
	var err error
	cfg.Development, err = envBool("AUTHD_DEVELOPMENT", false)
	if err != nil {
		return Config{}, err
	}
	cfg.TrustedProxies, err = trustedProxies(os.Getenv("AUTHD_TRUSTED_PROXIES"))
	if err != nil {
		return Config{}, err
	}
	for _, field := range []struct {
		name     string
		value    *time.Duration
		fallback time.Duration
	}{
		{"AUTHD_ACCESS_TOKEN_TTL", &cfg.AccessTokenTTL, 5 * time.Minute},
		{"AUTHD_AUTH_CODE_TTL", &cfg.AuthorizationCodeTTL, time.Minute},
		{"AUTHD_SESSION_IDLE_TTL", &cfg.SessionIdleTTL, 12 * time.Hour},
		{"AUTHD_SESSION_ABSOLUTE_TTL", &cfg.SessionAbsoluteTTL, 7 * 24 * time.Hour},
		{"AUTHD_REFRESH_IDLE_TTL", &cfg.RefreshIdleTTL, 30 * 24 * time.Hour},
		{"AUTHD_REFRESH_ABSOLUTE_TTL", &cfg.RefreshAbsoluteTTL, 90 * 24 * time.Hour},
		{"AUTHD_CLEANUP_INTERVAL", &cfg.CleanupInterval, time.Hour},
		{"AUTHD_AUDIT_RETENTION", &cfg.AuditRetention, 365 * 24 * time.Hour},
	} {
		*field.value, err = envDuration(field.name, field.fallback)
		if err != nil {
			return Config{}, err
		}
	}
	if cfg.Listen == "" {
		cfg.Listen = defaultListen
	}
	if cfg.Issuer == "" {
		return Config{}, errors.New("AUTHD_ISSUER is required")
	}
	issuer, err := url.Parse(cfg.Issuer)
	if err != nil || (issuer.Scheme != "https" && issuer.Scheme != "http") || issuer.Hostname() == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.ForceQuery || issuer.Fragment != "" || strings.Contains(cfg.Issuer, "#") {
		return Config{}, errors.New("AUTHD_ISSUER must be an absolute origin-style URL without query or fragment")
	}
	if issuer.Path != "" || issuer.RawPath != "" {
		return Config{}, errors.New("AUTHD_ISSUER must not contain a path")
	}
	if !cfg.Development && issuer.Scheme != "https" {
		return Config{}, errors.New("AUTHD_ISSUER must use https outside development mode")
	}
	host, port, listenErr := net.SplitHostPort(cfg.Listen)
	if listenErr != nil || !validPort(port) {
		return Config{}, errors.New("AUTHD_LISTEN must be host:port with a numeric port from 1 through 65535")
	}
	if issuer.Port() != "" && !validPort(issuer.Port()) {
		return Config{}, errors.New("AUTHD_ISSUER has an invalid port")
	}
	if cfg.Development && (!loopback(issuer.Hostname()) || !loopback(host)) {
		return Config{}, errors.New("development mode requires a loopback issuer and loopback listener")
	}
	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	cfg.MasterKey, err = masterKeyFromEnv()
	if err != nil {
		return Config{}, err
	}
	if cfg.AccessTokenTTL <= 0 || cfg.AuthorizationCodeTTL <= 0 || cfg.SessionIdleTTL <= 0 || cfg.SessionAbsoluteTTL <= 0 || cfg.RefreshIdleTTL <= 0 || cfg.RefreshAbsoluteTTL <= 0 || cfg.CleanupInterval <= 0 || cfg.AuditRetention <= 0 {
		return Config{}, errors.New("all configured TTL values must be positive")
	}
	if cfg.AccessTokenTTL < 30*time.Second || cfg.AccessTokenTTL > time.Hour {
		return Config{}, errors.New("access token TTL must be between 30 seconds and one hour")
	}
	if cfg.AuthorizationCodeTTL > time.Minute {
		return Config{}, errors.New("authorization code TTL must not exceed 60 seconds")
	}
	if cfg.SessionIdleTTL < time.Second || cfg.SessionAbsoluteTTL < time.Second {
		return Config{}, errors.New("session TTLs must be at least one second")
	}
	if cfg.SessionIdleTTL > cfg.SessionAbsoluteTTL {
		return Config{}, errors.New("session idle TTL cannot exceed session absolute TTL")
	}
	if cfg.RefreshIdleTTL > cfg.RefreshAbsoluteTTL {
		return Config{}, errors.New("refresh idle TTL cannot exceed refresh absolute TTL")
	}
	if cfg.CleanupInterval < time.Minute {
		return Config{}, errors.New("cleanup interval must be at least one minute")
	}
	if cfg.AuditRetention < 24*time.Hour {
		return Config{}, errors.New("audit retention must be at least 24 hours")
	}
	return cfg, nil
}

func trustedProxies(raw string) ([]netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 64 {
		return nil, errors.New("AUTHD_TRUSTED_PROXIES contains too many prefixes")
	}
	seen := map[netip.Prefix]bool{}
	out := make([]netip.Prefix, 0, len(parts))
	for _, item := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil {
			return nil, errors.New("AUTHD_TRUSTED_PROXIES must contain comma-separated CIDR prefixes")
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			return nil, errors.New("AUTHD_TRUSTED_PROXIES must not trust an entire address family")
		}
		if seen[prefix] {
			return nil, errors.New("AUTHD_TRUSTED_PROXIES contains a duplicate prefix")
		}
		seen[prefix] = true
		out = append(out, prefix)
	}
	return out, nil
}

func masterKeyFromEnv() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("AUTHD_MASTER_KEY"))
	path := strings.TrimSpace(os.Getenv("AUTHD_MASTER_KEY_FILE"))
	if raw != "" && path != "" {
		return nil, errors.New("set only one of AUTHD_MASTER_KEY and AUTHD_MASTER_KEY_FILE")
	}
	if raw != "" {
		return decodeMasterKey([]byte(raw))
	}
	if path == "" {
		return nil, errors.New("AUTHD_MASTER_KEY or AUTHD_MASTER_KEY_FILE is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open AUTHD_MASTER_KEY_FILE")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("AUTHD_MASTER_KEY_FILE must be a regular owner-only file (0600 or 0400)")
	}
	body, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(body) > 4096 {
		return nil, errors.New("cannot read valid master-key material")
	}
	return decodeMasterKey(body)
}

func decodeMasterKey(body []byte) ([]byte, error) {
	if len(body) == 32 {
		return append([]byte(nil), body...), nil
	}
	raw := strings.TrimSpace(string(body))
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(raw)
	}
	if err != nil {
		return nil, fmt.Errorf("master key must be 32 raw bytes or base64: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must decode to exactly 32 bytes, got %d", len(key))
	}
	return key, nil
}

func envBool(name string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", name)
	}
	return value, nil
}
func envDuration(name string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration", name)
	}
	return value, nil
}
func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func validPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == port
}
