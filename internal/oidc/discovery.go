package oidc

import "strings"

type Metadata struct {
	ResponseModesSupported                 []string `json:"response_modes_supported"`
	ClaimTypesSupported                    []string `json:"claim_types_supported"`
	ClaimsParameterSupported               bool     `json:"claims_parameter_supported"`
	RequestParameterSupported              bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported           bool     `json:"request_uri_parameter_supported"`
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported"`

	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	JWKSURI                                    string   `json:"jwks_uri"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	ACRValuesSupported                         []string `json:"acr_values_supported"`
	AuthorizationResponseISSParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

func NewMetadata(issuer string) Metadata {
	issuer = strings.TrimRight(issuer, "/")
	return Metadata{
		Issuer:                 issuer,
		ResponseModesSupported: []string{"query"}, ClaimTypesSupported: []string{"normal"},
		ClaimsParameterSupported:               true,
		RevocationEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		AuthorizationEndpoint:                  issuer + "/authorize",
		TokenEndpoint:                          issuer + "/token",
		UserinfoEndpoint:                       issuer + "/userinfo",
		JWKSURI:                                issuer + "/jwks.json",
		RevocationEndpoint:                     issuer + "/revoke",
		EndSessionEndpoint:                     issuer + "/logout",
		ResponseTypesSupported:                 []string{"code"},
		GrantTypesSupported:                    []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:                  []string{"public"},
		IDTokenSigningAlgValuesSupported:       []string{"RS256"},
		// client_secret_post exists specifically because bdcmaps uses it today.
		// New confidential clients should prefer client_secret_basic.
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ScopesSupported:                   []string{"openid", "profile", "email", "groups", "roles", "offline_access"},
		ClaimsSupported: []string{
			"sub", "name", "preferred_username", "email", "email_verified",
			"groups", "roles", "auth_time", "acr", "amr", "sid", "at_hash",
		},
		ACRValuesSupported:                         []string{ACRPassword, ACRMFA},
		AuthorizationResponseISSParameterSupported: true,
	}
}
