package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/akeyless-go-cloud-id/cloudprovider/aws"
	"github.com/akeylesslabs/akeyless-go-cloud-id/cloudprovider/azure"
	"github.com/akeylesslabs/akeyless-go-cloud-id/cloudprovider/gcp"
)

// saTokenEntry is one audience entry from csi.storage.k8s.io/serviceAccount.tokens.
type saTokenEntry struct {
	Token               string    `json:"token"`
	ExpirationTimestamp time.Time `json:"expirationTimestamp"`
}

// jwtNow is the clock used for ServiceAccount token expiry checks (overridable in tests).
var jwtNow = time.Now

// DefServiceAccountFile is the projected ServiceAccount token path used for
// Kubernetes (k8s) authentication. Overridable in tests.
var DefServiceAccountFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// authSession holds per-mount Akeyless credentials. Config is often copied by
// value, so the session lives behind a pointer shared across those copies.
type authSession struct {
	mu     sync.RWMutex
	token  string
	client *akeyless.V2ApiService
}

func (c *Config) ensureSession() {
	if c.session == nil {
		c.session = &authSession{}
	}
}

func (c *Config) setAuthToken(t string) {
	c.ensureSession()
	c.session.mu.Lock()
	defer c.session.mu.Unlock()
	c.session.token = t
}

// AuthToken returns the Akeyless session token for this mount.
func (c *Config) AuthToken() string {
	if c.session == nil {
		return ""
	}
	c.session.mu.RLock()
	defer c.session.mu.RUnlock()
	return c.session.token
}

// Client returns the Akeyless API client bound to this mount.
func (c *Config) Client() *akeyless.V2ApiService {
	if c.session == nil {
		return nil
	}
	return c.session.client
}

func (c *Config) authenticate(ctx context.Context, aklClient *akeyless.V2ApiService, authBody *akeyless.Auth) error {
	authBody.SetAccessId(c.AkeylessAccessID)

	authOut, _, err := aklClient.Auth(ctx).Body(*authBody).Execute()
	if err != nil {
		return fmt.Errorf("authentication failed %v, %w", c.AkeylessGatewayURL, err)
	}

	c.setAuthToken(authOut.GetToken())
	return nil
}

func (c *Config) authWithAccessKey(ctx context.Context, aklClient *akeyless.V2ApiService) error {
	authBody := akeyless.NewAuthWithDefaults()
	authBody.SetAccessType(string(AccessKey))
	authBody.SetAccessKey(c.AkeylessAccessKey)
	err := c.authenticate(ctx, aklClient, authBody)

	if err != nil {
		log.Printf("authWithAccessKey ERR: %v", err.Error())
	}
	return err
}

func (c *Config) authWithAWS(ctx context.Context, aklClient *akeyless.V2ApiService) error {
	authBody := akeyless.NewAuthWithDefaults()
	authBody.SetAccessType(string(AWSIAM))
	cloudId, err := aws.GetCloudId()
	if err != nil {
		return fmt.Errorf("requested access type %v but failed to get cloud ID, error: %v", AWSIAM, err)
	}
	authBody.SetCloudId(cloudId)
	err = c.authenticate(ctx, aklClient, authBody)

	if err != nil {
		log.Printf("authWithAWS ERR: %v", err.Error())
	}
	return err
}

func (c *Config) authWithAzure(ctx context.Context, aklClient *akeyless.V2ApiService) error {
	authBody := akeyless.NewAuthWithDefaults()
	authBody.SetAccessType(string(AzureAD))
	cloudId, err := azure.GetCloudId(c.AkeylessAzureObjectID)
	if err != nil {
		return fmt.Errorf("requested access type %v but failed to get cloud ID, error: %v", AzureAD, err)
	}
	authBody.SetCloudId(cloudId)
	err = c.authenticate(ctx, aklClient, authBody)

	if err != nil {
		log.Printf("authWithAzure ERR: %v", err.Error())
	}
	return err
}

func (c *Config) authWithGCP(ctx context.Context, aklClient *akeyless.V2ApiService) error {
	authBody := akeyless.NewAuthWithDefaults()
	authBody.SetAccessType(string(GCP))
	cloudId, err := gcp.GetCloudID(c.AkeylessGCPAudience)
	if err != nil {
		return fmt.Errorf("requested access type %v but failed to get cloud ID, error: %v", GCP, err)
	}
	authBody.SetCloudId(cloudId)
	err = c.authenticate(ctx, aklClient, authBody)

	if err != nil {
		log.Printf("authWithGCP ERR: %v", err.Error())
	}
	return err
}

func (c *Config) authWithK8S(ctx context.Context, aklClient *akeyless.V2ApiService) error {
	authBody := akeyless.NewAuthWithDefaults()
	authBody.SetAccessType(string(K8S))
	authBody.SetK8sAuthConfigName(c.AkeylessK8sAuthConfigName)
	jwtString, err := readK8SServiceAccountJWT()
	if err != nil {
		return fmt.Errorf("failed to read JWT with Kubernetes Auth from %v. error: %v", DefServiceAccountFile, err.Error())
	}
	authBody.SetK8sServiceAccountToken(jwtString)
	err = c.authenticate(ctx, aklClient, authBody)

	if err != nil {
		log.Printf("authWithK8s ERR: %v", err.Error())
	}
	return err
}

// authWithJWT authenticates using an Akeyless OAuth2.0/JWT auth method
// (API access-type=jwt) with the workload pod's ServiceAccount token from
// csi.storage.k8s.io/serviceAccount.tokens. The JWT itself is never logged.
func (c *Config) authWithJWT(ctx context.Context, aklClient *akeyless.V2ApiService) error {
	jwtToken, err := c.resolveJWT()
	if err != nil {
		return err
	}

	authBody := akeyless.NewAuthWithDefaults()
	authBody.SetAccessId(c.AkeylessAccessID)
	authBody.SetAccessType(string(JWT))
	authBody.SetJwt(jwtToken)
	authOut, httpResp, err := aklClient.Auth(ctx).Body(*authBody).Execute()
	if err != nil {
		status, reason := jwtAuthFailureDetail(httpResp, err)
		log.Printf("authWithJWT ERR: authentication failed against %s: %s, %s", c.AkeylessGatewayURL, status, reason)
		return fmt.Errorf("jwt/oauth2 authentication failed against %s: %s, %s", c.AkeylessGatewayURL, status, reason)
	}
	c.setAuthToken(authOut.GetToken())
	return nil
}

// resolveJWT returns the workload pod ServiceAccount token for the configured
// audience from csi.storage.k8s.io/serviceAccount.tokens. Static Secret/env
// JWTs are not used — kubelet rotates these tokens and the CSI driver
// republishes them on each mount.
func (c *Config) resolveJWT() (string, error) {
	audience := strings.TrimSpace(c.AkeylessJWTAudience)
	if audience == "" {
		return "", fmt.Errorf("akeylessJWTAudience is required for jwt/oauth2 authentication")
	}
	raw := strings.TrimSpace(c.ServiceAccountTokensJSON)
	if raw == "" {
		return "", fmt.Errorf("missing csi.storage.k8s.io/serviceAccount.tokens; configure tokenRequests on the secrets-store CSIDriver for audience %q", audience)
	}

	var tokens map[string]saTokenEntry
	if err := json.Unmarshal([]byte(raw), &tokens); err != nil {
		return "", fmt.Errorf("invalid csi.storage.k8s.io/serviceAccount.tokens JSON: %w", err)
	}
	entry, ok := tokens[audience]
	if !ok {
		return "", fmt.Errorf("no ServiceAccount token for audience %q in csi.storage.k8s.io/serviceAccount.tokens", audience)
	}
	token := strings.TrimSpace(entry.Token)
	if token == "" {
		return "", fmt.Errorf("empty ServiceAccount token for audience %q", audience)
	}
	if !entry.ExpirationTimestamp.IsZero() && !entry.ExpirationTimestamp.After(jwtNow()) {
		return "", fmt.Errorf("ServiceAccount token for audience %q expired at %s", audience, entry.ExpirationTimestamp.UTC().Format(time.RFC3339))
	}
	if !entry.ExpirationTimestamp.IsZero() {
		log.Printf("using workload ServiceAccount token for audience %q (expires %s)", audience, entry.ExpirationTimestamp.UTC().Format(time.RFC3339))
	} else {
		log.Printf("using workload ServiceAccount token for audience %q", audience)
	}
	return token, nil
}

// hasWorkloadJWT reports whether this mount has an audience and a
// serviceAccount.tokens payload so jwt/oauth2 can be attempted.
func (c *Config) hasWorkloadJWT() bool {
	return strings.TrimSpace(c.AkeylessJWTAudience) != "" && strings.TrimSpace(c.ServiceAccountTokensJSON) != ""
}

// jwtAuthFailureDetail returns an HTTP status and a short safe reason for
// jwt/oauth2 auth failures. It never includes the JWT or raw response body.
func jwtAuthFailureDetail(httpResp *http.Response, err error) (status, reason string) {
	status = "unknown"
	reason = "authentication failed"
	if httpResp != nil {
		status = strconv.Itoa(httpResp.StatusCode)
		switch {
		case httpResp.StatusCode == http.StatusUnauthorized:
			reason = "token expired or invalid"
		case httpResp.StatusCode == http.StatusForbidden:
			reason = "forbidden"
		case httpResp.StatusCode >= 500:
			reason = "gateway error"
		default:
			reason = "request failed"
		}
	} else if err != nil {
		reason = "request failed"
	}

	var apiErr akeyless.GenericOpenAPIError
	if errors.As(err, &apiErr) {
		if status == "unknown" {
			// SDK often sets Error() to the HTTP status line, e.g. "401 Unauthorized".
			if code, ok := leadingHTTPStatus(apiErr.Error()); ok {
				status = strconv.Itoa(code)
				if code == http.StatusUnauthorized {
					reason = "token expired or invalid"
				}
			}
		}
		if m, ok := apiErr.Model().(akeyless.JSONError); ok {
			msg := strings.ToLower(m.GetError())
			switch {
			case strings.Contains(msg, "expir"):
				reason = "token expired"
			case strings.Contains(msg, "audience"):
				reason = "audience mismatch"
			case strings.Contains(msg, "issuer"):
				reason = "untrusted issuer"
			}
		}
	}
	return status, reason
}

func leadingHTTPStatus(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 3 {
		return 0, false
	}
	code, err := strconv.Atoi(s[:3])
	if err != nil || code < 100 || code > 599 {
		return 0, false
	}
	return code, true
}

func (c *Config) rotateUIDToken(ctx context.Context, aklClient *akeyless.V2ApiService) error {
	currToken := c.AuthToken()

	log.Println("rotating UID token")
	body := akeyless.UidRotateToken{
		UidToken: akeyless.PtrString(currToken),
	}
	authOut, _, err := aklClient.UidRotateToken(ctx).Body(body).Execute()
	if err != nil {
		return fmt.Errorf("failed to rotate UID token %w", err)
	}
	newToken := authOut.GetToken()
	if newToken == "" {
		return fmt.Errorf("rotated uid token returned empty")
	}

	c.setAuthToken(newToken)
	log.Println("successfully rotated UID token")
	return nil
}

// readK8SServiceAccountJWT reads the JWT data for the Agent to submit to Akeyless Gateway.
func readK8SServiceAccountJWT() (string, error) {
	data, err := os.Open(DefServiceAccountFile)
	if err != nil {
		return "", err
	}
	defer data.Close()

	contentBytes, err := io.ReadAll(data)
	if err != nil {
		return "", err
	}

	a := strings.TrimSpace(string(contentBytes))

	return base64.StdEncoding.EncodeToString([]byte(a)), nil
}

// StartAuthentication is retained for callers that expect a post-Parse hook.
// Authentication already runs in Parse and stores the session on this Config.
// Background renewal was previously process-global and tied to the Mount RPC
// context (cancelled when Mount returns); CSI remount re-authenticates instead.
func (c *Config) StartAuthentication(ctx context.Context, closed chan bool) error {
	select {
	case closed <- true:
	default:
	}
	return nil
}
