package config

import (
	"encoding/base64"
	"errors"
	"fmt"
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
}

func Load() (Config, error) {
	cfg := Config{
		Issuer:               strings.TrimRight(strings.TrimSpace(os.Getenv("AUTHD_ISSUER")), "/"),
		Listen:               strings.TrimSpace(os.Getenv("AUTHD_LISTEN")),
		DatabaseURL:          strings.TrimSpace(os.Getenv("DATABASE_URL")),
		Development:          envBool("AUTHD_DEVELOPMENT", false),
		AccessTokenTTL:       envDuration("AUTHD_ACCESS_TOKEN_TTL", 5*time.Minute),
		AuthorizationCodeTTL: envDuration("AUTHD_AUTH_CODE_TTL", time.Minute),
		SessionIdleTTL:       envDuration("AUTHD_SESSION_IDLE_TTL", 12*time.Hour),
		SessionAbsoluteTTL:   envDuration("AUTHD_SESSION_ABSOLUTE_TTL", 7*24*time.Hour),
		RefreshIdleTTL:       envDuration("AUTHD_REFRESH_IDLE_TTL", 30*24*time.Hour),
		RefreshAbsoluteTTL:   envDuration("AUTHD_REFRESH_ABSOLUTE_TTL", 90*24*time.Hour),
	}
	if cfg.Listen == "" {
		cfg.Listen = defaultListen
	}
	if cfg.Issuer == "" {
		return Config{}, errors.New("AUTHD_ISSUER is required")
	}
	issuer, err := url.Parse(cfg.Issuer)
	if err != nil || issuer.Scheme == "" || issuer.Host == "" || issuer.RawQuery != "" || issuer.Fragment != "" {
		return Config{}, errors.New("AUTHD_ISSUER must be an absolute origin-style URL without query or fragment")
	}
	if issuer.Path != "" && issuer.Path != "/" {
		return Config{}, errors.New("AUTHD_ISSUER must not contain a path")
	}
	if !cfg.Development && issuer.Scheme != "https" {
		return Config{}, errors.New("AUTHD_ISSUER must use https outside development mode")
	}
	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	cfg.MasterKey, err = masterKeyFromEnv()
	if err != nil {
		return Config{}, err
	}
	if cfg.AccessTokenTTL <= 0 || cfg.AuthorizationCodeTTL <= 0 || cfg.SessionIdleTTL <= 0 || cfg.SessionAbsoluteTTL <= 0 || cfg.RefreshIdleTTL <= 0 || cfg.RefreshAbsoluteTTL <= 0 {
		return Config{}, errors.New("all configured TTL values must be positive")
	}
	if cfg.SessionIdleTTL > cfg.SessionAbsoluteTTL {
		return Config{}, errors.New("session idle TTL cannot exceed session absolute TTL")
	}
	if cfg.RefreshIdleTTL > cfg.RefreshAbsoluteTTL {
		return Config{}, errors.New("refresh idle TTL cannot exceed refresh absolute TTL")
	}
	return cfg, nil
}

func masterKeyFromEnv() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("AUTHD_MASTER_KEY"))
	if raw != "" {
		return decodeMasterKey([]byte(raw))
	}
	path := strings.TrimSpace(os.Getenv("AUTHD_MASTER_KEY_FILE"))
	if path == "" {
		return nil, errors.New("AUTHD_MASTER_KEY or AUTHD_MASTER_KEY_FILE is required")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read AUTHD_MASTER_KEY_FILE: %w", err)
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

func envBool(name string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}

func envDuration(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return value
}
