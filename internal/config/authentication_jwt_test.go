package config

import (
	"os"
	"path/filepath"
	"testing"

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

func TestParseParameters_JWTFromCSISecretNotFromAttributes(t *testing.T) {
	// JWT in SPC attributes must be ignored (avoid etcd-stored bearer tokens).
	attrs := `{"akeylessAccessType":"jwt","akeylessAccessID":"p-jwt","akeylessJWT":"should-be-ignored","objects":"- secretPath: /x\n  fileName: x"}`
	got, err := parseParameters("", attrs, defaultAkeylessGatewayURL, defaultVaultKubernetesMountPath)
	require.NoError(t, err)
	require.Empty(t, got.AkeylessJWT)

	secrets := `{"akeylessJWT":"header.payload.sig"}`
	got, err = parseParameters(secrets, attrs, defaultAkeylessGatewayURL, defaultVaultKubernetesMountPath)
	require.NoError(t, err)
	require.Equal(t, "header.payload.sig", got.AkeylessJWT)
}

func TestParseParameters_JWTFromEnv(t *testing.T) {
	t.Setenv(AkeylessJWT, "env.jwt.token")
	attrs := `{"akeylessAccessType":"jwt","akeylessAccessID":"p-jwt","objects":"- secretPath: /x\n  fileName: x"}`
	got, err := parseParameters("", attrs, defaultAkeylessGatewayURL, defaultVaultKubernetesMountPath)
	require.NoError(t, err)
	require.Equal(t, "env.jwt.token", got.AkeylessJWT)
}

func TestResolveJWT_PrefersConfiguredOverFile(t *testing.T) {
	cfg := &Config{Parameters: Parameters{AkeylessJWT: "  configured.jwt  "}}
	got, err := cfg.resolveJWT()
	require.NoError(t, err)
	require.Equal(t, "configured.jwt", got)
}

func TestResolveJWT_ReadsServiceAccountFile(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("  sa.jwt.token\n"), 0o600))

	orig := DefServiceAccountFile
	DefServiceAccountFile = tokenPath
	t.Cleanup(func() { DefServiceAccountFile = orig })

	cfg := &Config{}
	got, err := cfg.resolveJWT()
	require.NoError(t, err)
	require.Equal(t, "sa.jwt.token", got)
}

func TestResolveJWT_EmptySourcesError(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("   \n"), 0o600))

	orig := DefServiceAccountFile
	DefServiceAccountFile = tokenPath
	t.Cleanup(func() { DefServiceAccountFile = orig })

	cfg := &Config{}
	_, err := cfg.resolveJWT()
	require.Error(t, err)
}

func TestValidate_JWTRequiresAccessID(t *testing.T) {
	cfg := Config{
		TargetPath: "/mnt",
		Parameters: Parameters{
			AkeylessAccessType: string(JWT),
			Secrets:            []Secret{{FileName: "f", SecretPath: "/s"}},
		},
	}
	require.Error(t, cfg.validate())

	cfg.AkeylessAccessID = "p-jwt"
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
