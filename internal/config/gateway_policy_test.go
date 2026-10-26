package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCanonicalGatewayURL(t *testing.T) {
	got, err := canonicalGatewayURL("https://API.akeyless.io/")
	require.NoError(t, err)
	require.Equal(t, "https://api.akeyless.io/", got)

	_, err = canonicalGatewayURL("https://user:pass@api.akeyless.io")
	require.Error(t, err)
	_, err = canonicalGatewayURL("https://api.akeyless.io?x=1")
	require.Error(t, err)
	_, err = canonicalGatewayURL("https://api.akeyless.io#frag")
	require.Error(t, err)
	_, err = canonicalGatewayURL("ftp://api.akeyless.io")
	require.Error(t, err)
	_, err = canonicalGatewayURL("not-a-url")
	require.Error(t, err)
}

func TestTrustedGatewayURL_AllowsDefaultAndAllowlist(t *testing.T) {
	t.Setenv(AkeylessURL, "")
	t.Setenv(AkeylessAllowedGatewayURLs, "")

	got, err := trustedGatewayURL("https://api.akeyless.io", "https://api.akeyless.io")
	require.NoError(t, err)
	require.Equal(t, "https://api.akeyless.io", got)

	t.Setenv(AkeylessAllowedGatewayURLs, "https://gw.example.com:8080, https://backup.example.com")
	got, err = trustedGatewayURL("https://gw.example.com:8080", "https://api.akeyless.io")
	require.NoError(t, err)
	require.Equal(t, "https://gw.example.com:8080", got)

	_, err = trustedGatewayURL("https://evil.example", "https://api.akeyless.io")
	require.Error(t, err)
}

func TestTrustedGatewayURL_OperatorEnvDefault(t *testing.T) {
	t.Setenv(AkeylessURL, "https://operator-default.example")
	t.Setenv(AkeylessAllowedGatewayURLs, "")
	got, err := trustedGatewayURL("https://operator-default.example", "https://api.akeyless.io")
	require.NoError(t, err)
	require.Equal(t, "https://operator-default.example", got)
}
