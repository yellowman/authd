package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/identity"
)

func TestEssentialACRAndSubjectSelectors(t *testing.T) {
	for _, tc := range []struct {
		name, raw, minimum, want string
		bad                      bool
	}{
		{"MFA exact", `{"id_token":{"acr":{"essential":true,"value":"urn:authd:acr:mfa"}}}`, "", ACRMFA, false},
		{"unknown voluntary", `{"id_token":{"acr":{"value":"urn:unknown"}}}`, "", "", false},
		{"unknown essential", `{"id_token":{"acr":{"essential":true,"value":"urn:unknown"}}}`, "", "", true},
		{"minimum is not downgraded", `{"id_token":{"acr":{"essential":true,"value":"urn:authd:acr:pwd"}}}`, ACRMFA, "", true},
		{"no essential value constraint", `{"id_token":{"acr":{"essential":true}}}`, "", ACRPassword, false},
		{"ordered alternatives", `{"id_token":{"acr":{"essential":true,"values":["urn:unknown","urn:authd:acr:mfa"]}}}`, "", ACRMFA, false},
		{"duplicate JSON names", `{"id_token":{"acr":{"essential":false,"essential":true}}}`, "", "", true},
		{"scalar claims root", `[]`, "", "", true},
		{"sub list", `{"id_token":{"sub":{"values":["one","two"]}}}`, "", "", false},
		{"sub null value", `{"id_token":{"sub":{"value":null}}}`, "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			required, subjects, err := authenticationClaims(tc.raw, tc.minimum)
			if (err != nil) != tc.bad {
				t.Fatalf("err=%v bad=%v", err, tc.bad)
			}
			if !tc.bad && required != tc.want {
				t.Fatalf("required=%q want=%q", required, tc.want)
			}
			if tc.name == "sub list" && (!SubjectMatches(AuthorizationRequest{ExpectedSubjects: subjects}, "two") || SubjectMatches(AuthorizationRequest{ExpectedSubjects: subjects}, "three")) {
				t.Fatal("sub alternatives not enforced")
			}
		})
	}
}
func TestAuthenticationFreshnessAtCompletion(t *testing.T) {
	start := time.Now().UTC()
	age := int64(300)
	req := AuthorizationRequest{CreatedAt: start, MaxAgeSeconds: &age}
	auth := start.Add(-299 * time.Second)
	if !AuthenticationFresh(req, auth, start) || AuthenticationFresh(req, auth, start.Add(2*time.Second)) {
		t.Fatal("max_age was frozen at authorization start")
	}
	zero := int64(0)
	req.MaxAgeSeconds = &zero
	if AuthenticationFresh(req, start.Add(-time.Nanosecond), start) || !AuthenticationFresh(req, start.Add(time.Second), start.Add(time.Second)) {
		t.Fatal("max_age=0 did not require a new ceremony")
	}
	req = AuthorizationRequest{CreatedAt: start, Prompt: "select_account consent"}
	if AuthenticationFresh(req, auth, start) {
		t.Fatal("account selection reused an old session")
	}
}
func TestBrowserBoundAuthorizationContinuation(t *testing.T) {
	_, svc, store, _, session, _ := providerFixture(t)
	browser, _ := cryptoutil.RandomToken(32)
	other, _ := cryptoutil.RandomToken(32)
	flow, _, _, err := svc.BeginAuthorization(context.Background(), auditRequest(), browser, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if redirect, _, err := svc.ContinueAuthorization(context.Background(), flow, other, session, time.Now()); !errors.Is(err, ErrInvalidRequest) || redirect != "" {
		t.Fatalf("foreign browser resumed flow: %s %v", redirect, err)
	}
	if len(store.codes) != 0 {
		t.Fatal("foreign browser created a code")
	}
	redirect, _, err := svc.ContinueAuthorization(context.Background(), flow, browser, session, time.Now())
	if err != nil || !strings.Contains(redirect, "code=") {
		t.Fatalf("valid browser failed: %s %v", redirect, err)
	}
}
func TestOfflineAccessRequiresConsent(t *testing.T) {
	_, svc, _, _, _, _ := providerFixture(t)
	browser, _ := cryptoutil.RandomToken(32)
	for _, prompt := range []string{"", "none", "consent"} {
		q := auditRequest()
		q.Set("scope", "openid offline_access")
		if prompt != "" {
			q.Set("prompt", prompt)
		}
		_, req, _, err := svc.BeginAuthorization(context.Background(), q, browser, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if contains(req.Scopes, "offline_access") != (prompt == "consent") {
			t.Fatalf("offline scope retained without consent: %q", prompt)
		}
	}
}
func TestSelectiveClaimsDoNotReleaseEntireScope(t *testing.T) {
	_, svc, store, _, session, _ := providerFixture(t)
	browser, _ := cryptoutil.RandomToken(32)
	q := auditRequest()
	q.Set("claims", `{"id_token":{"name":null},"userinfo":{"email":null}}`)
	flow, req, _, err := svc.BeginAuthorization(context.Background(), q, browser, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(req.Scopes, " ") != "openid" {
		t.Fatal("claim selectors became implicit OAuth scopes")
	}
	redirect, _, err := svc.ContinueAuthorization(context.Background(), flow, browser, session, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redirect)
	verifier, _ := verifierAndChallenge()
	resp, err := svc.ExchangeCode(context.Background(), store.client, u.Query().Get("code"), store.client.RedirectURIs[0], verifier, time.Now(), identity.Audit{})
	if err != nil {
		t.Fatal(err)
	}
	var id map[string]any
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(resp.IDToken, ".")[1])
	if err = json.Unmarshal(payload, &id); err != nil {
		t.Fatal(err)
	}
	if id["name"] != "Alice" || id["email"] != nil || id["preferred_username"] != nil {
		t.Fatalf("ID claim selection leaked fields: %#v", id)
	}
	info, err := svc.UserInfo(context.Background(), resp.AccessToken, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if info["email"] != "alice@example.test" || info["email_verified"] != nil || info["name"] != nil || info["preferred_username"] != nil {
		t.Fatalf("UserInfo selection leaked fields: %#v", info)
	}
	// A selector cannot bypass the client's identity-claim allowlist.
	store.client.IdentityScopes = []string{"openid"}
	if _, _, _, err = svc.BeginAuthorization(context.Background(), q, browser, time.Now()); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("disallowed claim release: %v", err)
	}
}
func TestConsentCSRFAndDenial(t *testing.T) {
	h, _, store, _, session, _ := providerFixture(t)
	q := auditRequest()
	q.Set("scope", "openid offline_access")
	q.Set("prompt", "consent")
	r := httptest.NewRequest("GET", "https://auth.example.test/authorize?"+q.Encode(), nil)
	r.AddCookie(&http.Cookie{Name: h.cookieName("session"), Value: session})
	w := httptest.NewRecorder()
	muxFor(h).ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("no consent form: %d %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	form := interactionFields(t, w.Body.String())
	form.Set("decision", "deny")
	post := func(withBrowser bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://auth.example.test/authorize/consent", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: h.cookieName("session"), Value: session})
		if withBrowser {
			for _, c := range cookies {
				r.AddCookie(c)
			}
		}
		out := httptest.NewRecorder()
		muxFor(h).ServeHTTP(out, r)
		return out
	}
	if got := post(false); got.Code != 403 {
		t.Fatal("consent form was not browser-bound")
	}
	got := post(true)
	u, _ := url.Parse(got.Header().Get("Location"))
	if got.Code != 302 || u.Query().Get("error") != "access_denied" || len(store.codes) != 0 || len(store.requests) != 0 {
		t.Fatalf("consent denial had side effects or wrong redirect: %d %s", got.Code, u)
	}
}

type unavailableStore struct{ Store }

func (f unavailableStore) Client(context.Context, string) (Client, error) {
	return Client{}, errors.New("secret-dsn-must-not-escape")
}
func (f unavailableStore) PublicOriginAllowed(context.Context, string) (bool, error) {
	return false, errors.New("secret-dsn-must-not-escape")
}
func TestDependencyFailuresStayRetryableAndRedacted(t *testing.T) {
	h, svc, store, _, _, _ := providerFixture(t)
	svc.Store = unavailableStore{store}
	for _, origin := range []string{"", "https://rp.example.test"} {
		r := httptest.NewRequest("POST", "https://auth.example.test/token", strings.NewReader("grant_type=authorization_code&client_id=bdcmaps&client_secret=irrelevant"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		muxFor(h).ServeHTTP(w, r)
		if w.Code != 503 || strings.Contains(w.Body.String(), "secret-dsn") || strings.Contains(w.Body.String(), "invalid_client") {
			t.Fatalf("dependency failure became bad credentials/success: %d %s", w.Code, w.Body.String())
		}
	}
}

type unavailableLogout struct{ Sessions }

func (f unavailableLogout) EndSession(context.Context, string, identity.Audit) error {
	return errors.New("store unavailable")
}
func TestLogoutFailureDoesNotClearBrowserOrRedirect(t *testing.T) {
	h, svc, store, _, session, _ := providerFixture(t)
	svc.Sessions = unavailableLogout{svc.Sessions}
	sess := store.sessions[hashKey(identity.Hash(session))]
	g := CodeGrant{Client: store.client, Subject: Subject{ID: sess.User.ID, SessionID: sess.ID, AuthTime: sess.AuthTime, AuthMethods: sess.AuthMethods}, Scopes: []string{"openid"}}
	tokens, err := svc.tokensForGrant(context.Background(), g, time.Now(), false)
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{"id_token_hint": {tokens.IDToken}, "post_logout_redirect_uri": {store.client.LogoutURIs[0]}}
	r := httptest.NewRequest("GET", "https://auth.example.test/logout?"+q.Encode(), nil)
	r.AddCookie(&http.Cookie{Name: h.cookieName("session"), Value: session})
	w := httptest.NewRecorder()
	muxFor(h).ServeHTTP(w, r)
	if w.Code != 503 || w.Header().Get("Location") != "" || len(w.Result().Cookies()) != 0 {
		t.Fatalf("failed logout claimed success: %d %v", w.Code, w.Header())
	}
}
func TestUserInfoPostBodyAndTokenSeparation(t *testing.T) {
	h, svc, store, _, session, _ := providerFixture(t)
	sess := store.sessions[hashKey(identity.Hash(session))]
	g := CodeGrant{Client: store.client, Subject: Subject{ID: sess.User.ID, SessionID: sess.ID, AuthTime: sess.AuthTime, AuthMethods: sess.AuthMethods}, Scopes: []string{"openid"}}
	tr, err := svc.tokensForGrant(context.Background(), g, time.Now(), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body, header string
		want         int
	}{{tr.AccessToken, "", 200}, {tr.IDToken, "", 401}, {tr.AccessToken, tr.AccessToken, 400}} {
		r := httptest.NewRequest("POST", "https://auth.example.test/userinfo", strings.NewReader(url.Values{"access_token": {tc.body}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if tc.header != "" {
			r.Header.Set("Authorization", "Bearer "+tc.header)
		}
		w := httptest.NewRecorder()
		muxFor(h).ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("UserInfo token transport/type: got %d want %d: %s", w.Code, tc.want, w.Body.String())
		}
	}
	if _, _, _, err := svc.LogoutClient(context.Background(), tr.AccessToken, time.Now()); err == nil {
		t.Fatal("access token accepted as logout ID token")
	}
}
func TestSignedJWTRejectsDuplicateMembersAndJOSEExtensions(t *testing.T) {
	_, svc, store, _, _, _ := providerFixture(t)
	key, err := svc.cachedPrivateKey(store.keys[store.active])
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	payload := fmt.Sprintf(`{"iss":"https://auth.example.test","sub":"a","aud":"bdcmaps","iat":%d,"exp":%d}`, now.Unix(), now.Add(time.Minute).Unix())
	headers := []string{
		fmt.Sprintf(`{"alg":"RS256","kid":%q,"typ":"JWT","alg":"RS256"}`, store.active),
		fmt.Sprintf(`{"alg":"RS256","kid":%q,"typ":"JWT","crit":["x"],"x":true}`, store.active),
		fmt.Sprintf(`{"alg":"RS256","kid":%q,"typ":"JWT","b64":true}`, store.active),
	}
	for _, header := range headers {
		raw := independentJWT(t, key, header, payload)
		if _, err := verifyJWT(raw, &key.PublicKey, svc.issuer, now, true); err == nil {
			t.Fatalf("JOSE ambiguity accepted: %s", header)
		}
	}
	header := fmt.Sprintf(`{"alg":"RS256","kid":%q,"typ":"JWT"}`, store.active)
	duplicate := strings.TrimSuffix(payload, "}") + `,"sub":"b"}`
	if _, err := verifyJWT(independentJWT(t, key, header, duplicate), &key.PublicKey, svc.issuer, now, true); err == nil {
		t.Fatal("duplicate signed claim accepted")
	}
	if _, err := verifyJWT(independentJWT(t, key, header, payload), &key.PublicKey, svc.issuer, now, true); err != nil {
		t.Fatal("valid independently encoded fixture rejected:", err)
	}
}
func independentJWT(t *testing.T, key *rsa.PrivateKey, header, payload string) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func TestWrongMasterKeyFailsReadiness(t *testing.T) {
	_, svc, store, sessions, _, _ := providerFixture(t)
	wrong := sha256.Sum256([]byte("wrong master key"))
	bad, err := NewService(store, sessions, svc.issuer, wrong[:], time.Minute, time.Hour, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = bad.EnsureSigningKey(context.Background()); err == nil {
		t.Fatal("wrong key accepted at startup")
	}
	record := store.keys[store.active]
	record.PublicJWK = []byte(`{"kty":"RSA","use":"sig","alg":"RS256","kid":"wrong","n":"AQ","e":"AQAB"}`)
	if _, err = svc.cachedPrivateKey(record); err == nil {
		t.Fatal("cached signer hid a JWKS mismatch")
	}
}
func TestTokenIssuanceSizeLimitRollsBack(t *testing.T) {
	h, svc, store, _, session, _ := providerFixture(t)
	verifier, challenge := verifierAndChallenge()
	code := beginAndAuthorize(t, h, session, "openid profile offline_access", verifier, challenge)
	rec := store.codes[hashKey(identity.Hash(code))]
	rec.grant.Subject.DisplayName = strings.Repeat("x", maxJWTBytes)
	if _, err := svc.ExchangeCode(context.Background(), store.client, code, store.client.RedirectURIs[0], verifier, time.Now(), identity.Audit{}); err == nil {
		t.Fatal("oversized token issued")
	}
	if rec.consumed || len(store.refresh) != 0 {
		t.Fatal("failed encoding consumed a grant")
	}
	rec.grant.Subject.DisplayName = "Alice"
	if _, err := svc.ExchangeCode(context.Background(), store.client, code, store.client.RedirectURIs[0], verifier, time.Now(), identity.Audit{}); err != nil {
		t.Fatal("safe retry failed:", err)
	}
}
func TestDuplicateAndMalformedAuthorizationInput(t *testing.T) {
	h, _, _, _, _, _ := providerFixture(t)
	for _, extra := range []string{"&state=again", "&unknown=one&unknown=two", "&broken=%xx"} {
		r := httptest.NewRequest("GET", "https://auth.example.test/authorize?"+auditRequest().Encode()+extra, nil)
		w := httptest.NewRecorder()
		muxFor(h).ServeHTTP(w, r)
		if w.Code != 400 || w.Header().Get("Location") != "" {
			t.Fatalf("ambiguous input redirected or accepted: %d", w.Code)
		}
	}
}
func TestEmptySecondClientAuthenticationMethodRejected(t *testing.T) {
	h, _, _, _, _, secret := providerFixture(t)
	r := httptest.NewRequest("POST", "/token", nil)
	r.SetBasicAuth("bdcmaps", secret)
	if _, err := h.authenticateClient(r, url.Values{"client_secret": {""}}); err == nil {
		t.Fatal("Basic plus an empty second credential method accepted")
	}
}
func TestPKCERFC7636Vector(t *testing.T) {
	v := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	digest := sha256.Sum256([]byte(v))
	if !validVerifier(v) || !validPKCEChallenge(want) || base64.RawURLEncoding.EncodeToString(digest[:]) != want {
		t.Fatal("RFC7636 vector failed")
	}
}
func FuzzStrictSecurityJSON(f *testing.F) {
	for _, seed := range []string{`{}`, `{"sub":"a","sub":"b"}`, `{"id_token":{"acr":{"essential":true}}}`, `{"x":[1,{"y":null}]}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 8192 {
			return
		}
		err := uniqueJSONObject([]byte(raw))
		if err == nil {
			var obj map[string]json.RawMessage
			if e := json.Unmarshal([]byte(raw), &obj); e != nil || obj == nil {
				t.Fatalf("strict parser accepted nonobject: %v", e)
			}
		}
	})
}

func TestClaimValueConstraintsNeverFabricateClaims(t *testing.T) {
	_, svc, store, _, session, _ := providerFixture(t)
	browser, _ := cryptoutil.RandomToken(32)
	q := auditRequest()
	q.Set("claims", `{"id_token":{"name":{"essential":true,"value":"Mallory"},"email":{"values":["elsewhere@example.test","alice@example.test"]}},"userinfo":{"email_verified":{"value":true},"email":{"value":"elsewhere@example.test"}}}`)
	flow, _, _, err := svc.BeginAuthorization(context.Background(), q, browser, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	redirect, _, err := svc.ContinueAuthorization(context.Background(), flow, browser, session, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redirect)
	verifier, _ := verifierAndChallenge()
	response, err := svc.ExchangeCode(context.Background(), store.client, u.Query().Get("code"), store.client.RedirectURIs[0], verifier, time.Now(), identity.Audit{})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := base64.RawURLEncoding.DecodeString(strings.Split(response.IDToken, ".")[1])
	var claims map[string]any
	if err = json.Unmarshal(body, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["name"] != nil || claims["email"] != "alice@example.test" {
		t.Fatalf("normal claim mismatch fabricated a value: %#v", claims)
	}
	info, err := svc.UserInfo(context.Background(), response.AccessToken, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if info["email"] != nil {
		t.Fatalf("mismatched UserInfo value survived: %#v", info)
	}
	for _, raw := range []string{`{"id_token":{"name":{"value":null}}}`, `{"id_token":{"email_verified":{"value":"true"}}}`, `{"id_token":{"email":{"value":"x","values":["y"]}}}`, `{"id_token":{"sub":{"values":[]}}}`, `{"id_token":{"acr":{"essential":true,"values":[]}}}`} {
		q.Set("claims", raw)
		if _, _, _, err = svc.BeginAuthorization(context.Background(), q, browser, time.Now()); err == nil {
			t.Fatalf("invalid selector accepted: %s", raw)
		}
	}
}
func TestIgnoredOfflineAccessCannotLeaveEmptyGrant(t *testing.T) {
	_, svc, _, _, _, _ := providerFixture(t)
	browser, _ := cryptoutil.RandomToken(32)
	q := auditRequest()
	q.Set("scope", "offline_access")
	if _, _, _, err := svc.BeginAuthorization(context.Background(), q, browser, time.Now()); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("empty effective scope issued: %v", err)
	}
}
func TestRedirectURINeedsRealHostname(t *testing.T) {
	if validClientURI("https://:443/callback") {
		t.Fatal("empty hostname accepted")
	}
}
