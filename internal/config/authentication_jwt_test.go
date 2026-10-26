package config

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIsJWTAccessType(t *testing.T) {
	require.True(t, isJWTAccessType("jwt"))
	require.True(t, isJWTAccessType("oauth2"))
	require.False(t, isJWTAccessType("k8s"))
	require.False(t, isJWTAccessType("access_key"))
	require.False(t, isJWTAccessType(""))
}

func TestParseParameters_NormalizesOAuth2Alias(t *testing.T) {
	params := `{"akeylessAccessType":"oauth2","akeylessAccessID":"p-jwt","objects":"- secretPath: /x\n  fileName: x"}`
	got, err := parseParameters("", params, defaultAkeylessGatewayURL, defaultVaultKubernetesMountPath)
	require.NoError(t, err)
	require.Equal(t, "jwt", got.AkeylessAccessType)
	require.Equal(t, "p-jwt", got.AkeylessAccessID)
}

func TestParseParameters_ReadsServiceAccountTokensAndAudience(t *testing.T) {
	tokens := map[string]saTokenEntry{
		"akeyless.io": {
			Token:               "pod.sa.token",
			ExpirationTimestamp: time.Now().Add(time.Hour),
		},
	}
	tokensJSON, err := json.Marshal(tokens)
	require.NoError(t, err)

	attrs := map[string]string{
		"akeylessAccessType":            "jwt",
		"akeylessAccessID":              "p-jwt",
		"akeylessJWTAudience":           "akeyless.io",
		"akeylessJWT":                   "should-be-ignored",
		csiServiceAccountTokensAttr:     string(tokensJSON),
		"objects":                       "- secretPath: /x\n  fileName: x",
	}
	paramsBytes, err := json.Marshal(attrs)
	require.NoError(t, err)

	// Static JWT in CSI secret must also be ignored.
	secrets := `{"akeylessJWT":"static.should.ignore"}`
	got, err := parseParameters(secrets, string(paramsBytes), defaultAkeylessGatewayURL, defaultVaultKubernetesMountPath)
	require.NoError(t, err)
	require.Equal(t, "akeyless.io", got.AkeylessJWTAudience)
	require.Equal(t, string(tokensJSON), got.ServiceAccountTokensJSON)
	require.True(t, got.accessTypeExplicit)
}

func TestParseParameters_AccessTypeExplicitFlag(t *testing.T) {
	t.Setenv(AkeylessAccessType, "")
	omitted := `{"akeylessAccessID":"p-1","objects":"- secretPath: /x\n  fileName: x"}`
	got, err := parseParameters("", omitted, defaultAkeylessGatewayURL, defaultVaultKubernetesMountPath)
	require.NoError(t, err)
	require.Equal(t, "access_key", got.AkeylessAccessType)
	require.False(t, got.accessTypeExplicit)

	explicit := `{"akeylessAccessType":"aws_iam","akeylessAccessID":"p-1","objects":"- secretPath: /x\n  fileName: x"}`
	got, err = parseParameters("", explicit, defaultAkeylessGatewayURL, defaultVaultKubernetesMountPath)
	require.NoError(t, err)
	require.Equal(t, "aws_iam", got.AkeylessAccessType)
	require.True(t, got.accessTypeExplicit)
}

func TestResolveJWT_SelectsTokenByAudience(t *testing.T) {
	tokens := map[string]saTokenEntry{
		"other": {
			Token:               "wrong.token",
			ExpirationTimestamp: time.Now().Add(time.Hour),
		},
		"akeyless.io": {
			Token:               "correct.token",
			ExpirationTimestamp: time.Now().Add(time.Hour),
		},
	}
	raw, err := json.Marshal(tokens)
	require.NoError(t, err)

	cfg := &Config{Parameters: Parameters{
		AkeylessJWTAudience:      "akeyless.io",
		ServiceAccountTokensJSON: string(raw),
	}}
	got, err := cfg.resolveJWT()
	require.NoError(t, err)
	require.Equal(t, "correct.token", got)
	require.True(t, cfg.hasWorkloadJWT())
}

func TestResolveJWT_MissingAudienceError(t *testing.T) {
	cfg := &Config{Parameters: Parameters{
		ServiceAccountTokensJSON: `{"akeyless.io":{"token":"t","expirationTimestamp":"2099-01-01T00:00:00Z"}}`,
	}}
	_, err := cfg.resolveJWT()
	require.Error(t, err)
	require.Contains(t, err.Error(), "akeylessJWTAudience")
}

func TestResolveJWT_AudienceNotInTokensError(t *testing.T) {
	cfg := &Config{Parameters: Parameters{
		AkeylessJWTAudience:      "missing-aud",
		ServiceAccountTokensJSON: `{"akeyless.io":{"token":"t","expirationTimestamp":"2099-01-01T00:00:00Z"}}`,
	}}
	_, err := cfg.resolveJWT()
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing-aud")
}

func TestResolveJWT_ExpiredTokenError(t *testing.T) {
	orig := jwtNow
	jwtNow = func() time.Time { return time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { jwtNow = orig })

	tokens := map[string]saTokenEntry{
		"akeyless.io": {
			Token:               "expired.token",
			ExpirationTimestamp: time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC),
		},
	}
	raw, err := json.Marshal(tokens)
	require.NoError(t, err)

	cfg := &Config{Parameters: Parameters{
		AkeylessJWTAudience:      "akeyless.io",
		ServiceAccountTokensJSON: string(raw),
	}}
	_, err = cfg.resolveJWT()
	require.Error(t, err)
	require.Contains(t, err.Error(), "expired")
}

func TestResolveJWT_UsesRotatedTokenOnNextMount(t *testing.T) {
	makeTokens := func(token string) string {
		tokens := map[string]saTokenEntry{
			"akeyless.io": {
				Token:               token,
				ExpirationTimestamp: time.Now().Add(time.Hour),
			},
		}
		raw, err := json.Marshal(tokens)
		require.NoError(t, err)
		return string(raw)
	}

	first := &Config{Parameters: Parameters{
		AkeylessJWTAudience:      "akeyless.io",
		ServiceAccountTokensJSON: makeTokens("token.v1"),
	}}
	got, err := first.resolveJWT()
	require.NoError(t, err)
	require.Equal(t, "token.v1", got)

	// A remount parses a fresh Config with kubelet's rotated token.
	second := &Config{Parameters: Parameters{
		AkeylessJWTAudience:      "akeyless.io",
		ServiceAccountTokensJSON: makeTokens("token.v2"),
	}}
	got, err = second.resolveJWT()
	require.NoError(t, err)
	require.Equal(t, "token.v2", got)
}

func TestResolveJWT_MissingTokensError(t *testing.T) {
	cfg := &Config{Parameters: Parameters{AkeylessJWTAudience: "akeyless.io"}}
	_, err := cfg.resolveJWT()
	require.Error(t, err)
	require.Contains(t, err.Error(), "serviceAccount.tokens")
}

func TestValidate_JWTRequiresAccessIDAudienceAndToken(t *testing.T) {
	cfg := Config{
		TargetPath: "/mnt",
		Parameters: Parameters{
			AkeylessAccessType: string(JWT),
			Secrets:            []Secret{{FileName: "f", SecretPath: "/s"}},
		},
	}
	require.Error(t, cfg.validate())

	cfg.AkeylessAccessID = "p-jwt"
	require.Error(t, cfg.validate())

	cfg.AkeylessJWTAudience = "akeyless.io"
	require.Error(t, cfg.validate())

	tokens := map[string]saTokenEntry{
		"akeyless.io": {
			Token:               "pod.sa.token",
			ExpirationTimestamp: time.Now().Add(time.Hour),
		},
	}
	raw, err := json.Marshal(tokens)
	require.NoError(t, err)
	cfg.ServiceAccountTokensJSON = string(raw)
	require.NoError(t, cfg.validate())
}

func TestUsingJWT(t *testing.T) {
	cfg := Config{Parameters: Parameters{AkeylessAccessType: "jwt"}}
	require.True(t, cfg.UsingJWT())
	cfg.AkeylessAccessType = "oauth2"
	require.True(t, cfg.UsingJWT())
	cfg.AkeylessAccessType = "k8s"
	require.False(t, cfg.UsingJWT())
}

func TestJWTAuthFailureDetail(t *testing.T) {
	status, reason := jwtAuthFailureDetail(&http.Response{StatusCode: 401}, nil)
	require.Equal(t, "401", status)
	require.Equal(t, "token expired or invalid", reason)

	status, reason = jwtAuthFailureDetail(&http.Response{StatusCode: 403}, nil)
	require.Equal(t, "403", status)
	require.Equal(t, "forbidden", reason)

	status, reason = jwtAuthFailureDetail(nil, errors.New("dial tcp: connection refused"))
	require.Equal(t, "unknown", status)
	require.Equal(t, "request failed", reason)

	code, ok := leadingHTTPStatus("401 Unauthorized")
	require.True(t, ok)
	require.Equal(t, 401, code)
}
