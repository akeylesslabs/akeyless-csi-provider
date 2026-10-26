package config

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/akeyless-go-cloud-id/cloudprovider/aws"
	"github.com/akeylesslabs/akeyless-go-cloud-id/cloudprovider/azure"
	"github.com/akeylesslabs/akeyless-go-cloud-id/cloudprovider/gcp"
)

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
// (API access-type=jwt). Requires an explicit JWT from the mount CSI secret
// or AKEYLESS_JWT. The JWT itself is never logged.
func (c *Config) authWithJWT(ctx context.Context, aklClient *akeyless.V2ApiService) error {
	jwtToken, err := c.resolveJWT()
	if err != nil {
		return err
	}

	authBody := akeyless.NewAuthWithDefaults()
	authBody.SetAccessType(string(JWT))
	authBody.SetJwt(jwtToken)
	err = c.authenticate(ctx, aklClient, authBody)
	if err != nil {
		// Do not include the JWT or raw API/error body in logs or returned errors.
		log.Printf("authWithJWT ERR: authentication failed against %s", c.AkeylessGatewayURL)
		return fmt.Errorf("jwt/oauth2 authentication failed against %s", c.AkeylessGatewayURL)
	}
	return nil
}

// resolveJWT returns the bearer JWT for oauth2/jwt auth.
// Priority on each auth attempt (first match wins):
//  1. CSI secret captured on Config for this mount
//  2. AKEYLESS_JWT, only when this mount did not set a JWT
func (c *Config) resolveJWT() (string, error) {
	if jwt := strings.TrimSpace(c.AkeylessJWT); jwt != "" {
		return jwt, nil
	}
	if jwt := strings.TrimSpace(os.Getenv(AkeylessJWT)); jwt != "" {
		return jwt, nil
	}
	return "", fmt.Errorf("empty JWT for oauth2/jwt auth (set CSI secret akeylessJWT or env %s)", AkeylessJWT)
}

// hasExplicitJWT reports whether this mount supplied a JWT via CSI secret or env.
func (c *Config) hasExplicitJWT() bool {
	return strings.TrimSpace(c.AkeylessJWT) != "" || strings.TrimSpace(os.Getenv(AkeylessJWT)) != ""
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
