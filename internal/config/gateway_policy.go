package config

import (
	"errors"
	"net/url"
	"os"
	"strings"
)

// AkeylessAllowedGatewayURLs is configured by the provider operator, never SPCs.
// Comma-separated list of additional allowed gateway base URLs.
const AkeylessAllowedGatewayURLs = "AKEYLESS_ALLOWED_GATEWAY_URLS"

func canonicalGatewayURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil {
		return "", errors.New("invalid Akeyless gateway URL")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.Hostname() == "" || u.Opaque != "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("invalid Akeyless gateway URL")
	}
	u.Host = strings.ToLower(u.Host)
	// Keep the base path (including escapes) exact; the SDK appends API paths.
	return u.String(), nil
}

// trustedGatewayURL authorizes the exact gateway base URL against operator
// configuration before any authentication or cloud identity acquisition.
// Allowed endpoints come from AKEYLESS_URL / defaultURL and
// AKEYLESS_ALLOWED_GATEWAY_URLS — never from SPC attributes alone.
func trustedGatewayURL(requested, defaultURL string) (string, error) {
	requested, err := canonicalGatewayURL(requested)
	if err != nil {
		return "", err
	}
	operatorDefault := strings.TrimSpace(os.Getenv(AkeylessURL))
	if operatorDefault == "" {
		operatorDefault = defaultURL
	}
	allowed := append([]string{operatorDefault}, strings.Split(os.Getenv(AkeylessAllowedGatewayURLs), ",")...)
	for _, raw := range allowed {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		candidate, err := canonicalGatewayURL(raw)
		if err != nil {
			return "", errors.New("invalid provider gateway allowlist configuration")
		}
		if candidate == requested {
			return requested, nil
		}
	}
	return "", errors.New("Akeyless gateway is not allowed by provider configuration")
}
