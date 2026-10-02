package oidc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"
)

// Parse only the bounded normal-claim selectors supported by authd. Other
// optional claims are not a source of authority; profile release remains scoped.
type claimSelector struct {
	Essential bool              `json:"essential"`
	Value     json.RawMessage   `json:"value"`
	Values    []json.RawMessage `json:"values"`
}

func authenticationClaims(raw string, minimum string) (required string, expectedSubjects []string, err error) {
	required = minimum
	if raw == "" {
		return
	}
	if len(raw) > 8192 || uniqueJSONObject([]byte(raw)) != nil {
		err = ErrInvalidRequest
		return
	}
	var request struct {
		IDToken  map[string]claimSelector `json:"id_token"`
		UserInfo map[string]claimSelector `json:"userinfo"`
	}
	if json.Unmarshal([]byte(raw), &request) != nil {
		err = ErrInvalidRequest
		return
	}
	sub, ok := request.IDToken["sub"]
	if ok {
		values, e := selectorValues(sub)
		if e != nil {
			err = e
			return
		}
		for _, rawValue := range values {
			var value string
			if json.Unmarshal(rawValue, &value) != nil || value == "" || len(value) > 255 {
				err = ErrInvalidRequest
				return
			}
			expectedSubjects = append(expectedSubjects, value)
		}
	}
	acr, ok := request.IDToken["acr"]
	if !ok || !acr.Essential {
		return
	}
	rawValues, e := selectorValues(acr)
	if e != nil {
		err = e
		return
	}
	values := []string{}
	for _, rv := range rawValues {
		var v string
		if string(rv) == "null" || json.Unmarshal(rv, &v) != nil {
			err = ErrInvalidRequest
			return
		}
		values = append(values, v)
	}
	// Essential with no value constraint means return an available ACR. It does
	// not mean MFA; returning pwd is correct unless client policy requires MFA.
	if len(values) == 0 {
		if required == "" {
			required = ACRPassword
		}
		return
	}
	for _, v := range values {
		if (v == ACRPassword || v == ACRMFA) && (minimum != ACRMFA || v == ACRMFA) {
			required = v
			return
		}
	}
	err = ErrUnmetAuthn
	return
}

// Duplicate JSON member names are rejected at every nesting level; security
// selectors must not acquire meaning from a parser's first/last-wins behavior.
func uniqueJSONObject(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return errors.New("JSON nesting too deep")
		}
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			names := map[string]bool{}
			for dec.More() {
				tok, err = dec.Token()
				if err != nil {
					return err
				}
				name, ok := tok.(string)
				if !ok || names[name] {
					return errors.New("duplicate JSON member")
				}
				names[name] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON")
		}
		_, err = dec.Token()
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
		return errors.New("JSON object required")
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func parsePrompt(raw string) (string, error) {
	if len(raw) > 128 {
		return "", ErrInvalidRequest
	}
	seen := map[string]bool{}
	values := strings.Fields(raw)
	for _, v := range values {
		if v != "none" && v != "login" && v != "consent" && v != "select_account" {
			return "", ErrInvalidRequest
		}
		if seen[v] {
			return "", ErrInvalidRequest
		}
		seen[v] = true
	}
	if seen["none"] && len(values) != 1 {
		return "", ErrInvalidRequest
	}
	return strings.Join(values, " "), nil
}
func hasPrompt(req AuthorizationRequest, prompt string) bool {
	return contains(strings.Fields(req.Prompt), prompt)
}

// Both transport and durable issuance use this same freshness rule. max_age is
// evaluated at completion, not frozen at request creation. NumericDate has
// one-second resolution; max_age=0 forces a ceremony after this transaction began.
func AuthenticationFresh(req AuthorizationRequest, authenticated, now time.Time) bool {
	if authenticated.IsZero() || authenticated.After(now.Add(time.Second)) {
		return false
	}
	if (hasPrompt(req, "login") || hasPrompt(req, "select_account") || (req.MaxAgeSeconds != nil && *req.MaxAgeSeconds == 0)) && authenticated.Before(req.CreatedAt) {
		return false
	}
	if req.MaxAgeSeconds != nil && *req.MaxAgeSeconds > 0 && now.Unix()-authenticated.Unix() > *req.MaxAgeSeconds {
		return false
	}
	return true
}
func ConsentNeeded(req AuthorizationRequest, sessionID string, prior ConsentApproval) bool {
	if req.ConsentSessionID == sessionID && sessionID != "" {
		return false
	}
	if hasPrompt(req, "consent") {
		return true
	}
	if !contains(req.Scopes, "offline_access") {
		return false
	}
	if prior.ApprovedAt.IsZero() {
		return true
	}
	for _, pair := range []struct{ requested, approved []string }{
		{req.Scopes, prior.Scopes}, {req.Claims.IDToken, prior.IDTokenClaims}, {req.Claims.UserInfo, prior.UserInfoClaims},
	} {
		for _, value := range pair.requested {
			if !contains(pair.approved, value) {
				return true
			}
		}
	}
	return false
}
func ResultACR(req AuthorizationRequest, methods []string) string {
	// An essential selector is an exact claim-value promise. A stronger ceremony
	// can satisfy pwd, but the returned ACR still names the selected context.
	if req.RequiredACR != "" {
		return req.RequiredACR
	}
	return acrForMethods(methods)
}

var claimScope = map[string]string{"name": "profile", "preferred_username": "profile", "email": "email", "email_verified": "email"}

// Only normal identity claims are selectable. roles/groups retain their explicit
// scopes; arbitrary custom claims cannot become injected permissions or tenant IDs.
func identityClaimSelection(raw string, client Client) (ClaimSelection, error) {
	var out ClaimSelection
	if raw == "" {
		return out, nil
	}
	var request struct {
		IDToken  map[string]claimSelector `json:"id_token"`
		UserInfo map[string]claimSelector `json:"userinfo"`
	}
	if json.Unmarshal([]byte(raw), &request) != nil {
		return out, ErrInvalidRequest
	}
	for _, part := range []struct {
		claims   map[string]claimSelector
		selected *[]string
		filters  *map[string][]json.RawMessage
	}{{request.IDToken, &out.IDToken, &out.IDTokenValues}, {request.UserInfo, &out.UserInfo, &out.UserInfoValues}} {
		for name, selector := range part.claims {
			scope, known := claimScope[name]
			if !known {
				continue
			}
			if !contains(client.IdentityScopes, scope) {
				return ClaimSelection{}, ErrInvalidScope
			}
			values, err := selectorValues(selector)
			if err != nil {
				return ClaimSelection{}, err
			}
			for _, rawValue := range values {
				if name == "email_verified" {
					var v bool
					if string(rawValue) == "null" || json.Unmarshal(rawValue, &v) != nil {
						return ClaimSelection{}, ErrInvalidRequest
					}
				} else {
					var v string
					if string(rawValue) == "null" || json.Unmarshal(rawValue, &v) != nil {
						return ClaimSelection{}, ErrInvalidRequest
					}
				}
			}
			if len(values) > 0 {
				if *part.filters == nil {
					*part.filters = map[string][]json.RawMessage{}
				}
				(*part.filters)[name] = values
			}
			*part.selected = append(*part.selected, name)
		}
		sort.Strings(*part.selected)
	}
	return out, nil
}
func ClientAllowsClaims(client Client, selection ClaimSelection) bool {
	for _, list := range [][]string{selection.IDToken, selection.UserInfo} {
		for _, name := range list {
			scope, known := claimScope[name]
			if !known || !contains(client.IdentityScopes, scope) {
				return false
			}
		}
	}
	return true
}

func SubjectMatches(req AuthorizationRequest, subject string) bool {
	return len(req.ExpectedSubjects) == 0 || contains(req.ExpectedSubjects, subject)
}

func selectorValues(v claimSelector) ([]json.RawMessage, error) {
	if len(v.Value) > 0 && v.Values != nil || v.Values != nil && len(v.Values) == 0 || len(v.Values) > 16 {
		return nil, ErrInvalidRequest
	}
	if len(v.Value) > 0 {
		return []json.RawMessage{v.Value}, nil
	}
	return v.Values, nil
}

// If both ACR syntaxes appear, essential claims take precedence. Core leaves
// that combination unspecified; our deterministic policy is documented.
func voluntaryClaimACR(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	var v struct {
		IDToken map[string]claimSelector `json:"id_token"`
	}
	if json.Unmarshal([]byte(raw), &v) != nil {
		return "", ErrInvalidRequest
	}
	a, ok := v.IDToken["acr"]
	if !ok || a.Essential {
		return "", nil
	}
	values, err := selectorValues(a)
	if err != nil {
		return "", err
	}
	for _, raw := range values {
		var val string
		if json.Unmarshal(raw, &val) != nil {
			return "", ErrInvalidRequest
		}
		if val == ACRPassword || val == ACRMFA {
			return val, nil
		}
	}
	return "", nil
}
