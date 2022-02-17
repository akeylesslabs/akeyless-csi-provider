package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/akeylesslabs/akeyless-go/v2"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/types"
)

const (
	AkeylessURL           = "AKEYLESS_URL"
	AkeylessAccessType    = "AKEYLESS_ACCESS_TYPE"
	AkeylessAccessID      = "AKEYLESS_ACCESS_ID"
	AkeylessAccessKey     = "AKEYLESS_ACCESS_KEY"
	AkeylessAzureObjectID = "AKEYLESS_AZURE_OBJECT_ID"
	AkeylessGCPAudience   = "AKEYLESS_GCP_AUDIENCE"
	AkeylessUIDInitToken  = "AKEYLESS_UID_INIT_TOKEN"
)

type accessType string

const (
	AccessKey         accessType = "access_key"
	AWSIAM            accessType = "aws_iam"
	AzureAD           accessType = "azure_ad"
	GCP               accessType = "gcp"
	UniversalIdentity accessType = "universal_identity"
)

var (
	AklClient *akeyless.V2ApiService
)

// Config represents all of the provider's configurable behaviour from the MountRequest proto message:
// * Parameters from the `Attributes` field.
// * Plus the rest of the proto fields we consume.
// See sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1/service.pb.go
type Config struct {
	Parameters
	TargetPath     string
	FilePermission os.FileMode
}

// Parameters stores the parameters specified in a mount request's `Attributes` field.
// It consists of the parameters section from the SecretProviderClass being mounted
// and pod metadata provided by the driver.
//
// Top-level values that aren't strings are not directly deserialisable because
// they are defined as literal string types:
// https://github.com/kubernetes-sigs/secrets-store-csi-driver/blob/0ba9810d41cc2dc336c68251d45ebac19f2e7f28/apis/v1alpha1/secretproviderclass_types.go#L59
//
// So we just deserialise by hand to avoid complexity and two passes.
type Parameters struct {
	VaultAddress             string
	VaultRoleName            string
	VaultKubernetesMountPath string
	VaultNamespace           string
	VaultTLSConfig           TLSConfig
	Secrets                  []Secret
	PodInfo                  PodInfo

	AkeylessAccessType    string
	AkeylessAccessID      string
	AkeylessAccessKey     string
	AkeylessAzureObjectID string
	AkeylessGCPAudience   string
	AkeylessUIDInitToken  string
}

type TLSConfig struct {
	CACertPath     string
	CADirectory    string
	TLSServerName  string
	SkipVerify     bool
	ClientCertPath string
	ClientKeyPath  string
}

type PodInfo struct {
	Name               string
	UID                types.UID
	Namespace          string
	ServiceAccountName string
}

type Secret struct {
	ObjectName string                 `yaml:"objectName,omitempty"`
	SecretPath string                 `yaml:"secretPath,omitempty"`
	SecretType string                 `yaml:"secretType,omitempty"`
	SecretArgs map[string]interface{} `yaml:"secretArgs,omitempty"`
}

func Parse(parametersStr, targetPath, permissionStr string, defaultVaultAddr string, defaultVaultKubernetesMountPath string) (Config, error) {
	config := Config{
		TargetPath: targetPath,
	}

	var err error
	config.Parameters, err = parseParameters(parametersStr, defaultVaultAddr, defaultVaultKubernetesMountPath)
	if err != nil {
		return Config{}, err
	}

	AklClient = createClient(config.VaultAddress)
	if config.Parameters.AkeylessAccessType == "" {
		config.Parameters.AkeylessAccessType = string(config.detectAccessType(AklClient))

		if config.Parameters.AkeylessAccessType == "" {
			return Config{}, fmt.Errorf("failed to detect access type of %s", config.AkeylessAccessID)
		}
		log.Printf("successfully connected using %s access type", config.AkeylessAccessType)
	}

	err = json.Unmarshal([]byte(permissionStr), &config.FilePermission)
	if err != nil {
		return Config{}, err
	}

	err = config.validate()
	if err != nil {
		return Config{}, err
	}

	return config, nil
}

func parseParameters(parametersStr string, defaultVaultAddress string, defaultVaultKubernetesMountPath string) (Parameters, error) {
	var params map[string]string
	err := json.Unmarshal([]byte(parametersStr), &params)
	if err != nil {
		return Parameters{}, err
	}

	var parameters Parameters
	parameters.VaultRoleName = params["roleName"]
	parameters.VaultAddress = params["vaultAddress"]
	parameters.VaultNamespace = params["vaultNamespace"]
	parameters.VaultTLSConfig.CACertPath = params["vaultCACertPath"]
	parameters.VaultTLSConfig.CADirectory = params["vaultCADirectory"]
	parameters.VaultTLSConfig.TLSServerName = params["vaultTLSServerName"]
	parameters.VaultTLSConfig.ClientCertPath = params["vaultTLSClientCertPath"]
	parameters.VaultTLSConfig.ClientKeyPath = params["vaultTLSClientKeyPath"]
	parameters.VaultKubernetesMountPath = params["vaultKubernetesMountPath"]
	parameters.PodInfo.Name = params["csi.storage.k8s.io/pod.name"]
	parameters.PodInfo.UID = types.UID(params["csi.storage.k8s.io/pod.uid"])
	parameters.PodInfo.Namespace = params["csi.storage.k8s.io/pod.namespace"]
	parameters.PodInfo.ServiceAccountName = params["csi.storage.k8s.io/serviceAccount.name"]
	parameters.AkeylessAccessType = params["akeylessAccessType"]
	parameters.AkeylessAccessID = params["akeylessAccessID"]
	parameters.AkeylessAccessKey = params["akeylessAccessKey"]
	parameters.AkeylessAzureObjectID = params["akeylessAzureObjectID"]
	parameters.AkeylessGCPAudience = params["akeylessGCPAudience"]
	parameters.AkeylessUIDInitToken = params["akeylessUIDInitToken"]

	if skipTLS, ok := params["vaultSkipTLSVerify"]; ok {
		value, err := strconv.ParseBool(skipTLS)
		if err == nil {
			parameters.VaultTLSConfig.SkipVerify = value
		} else {
			return Parameters{}, err
		}
	}

	secretsYaml := params["objects"]
	err = yaml.Unmarshal([]byte(secretsYaml), &parameters.Secrets)
	if err != nil {
		return Parameters{}, err
	}

	if parameters.VaultAddress == "" {
		parameters.VaultAddress = os.Getenv(AkeylessURL)
	}

	if parameters.AkeylessAccessType == "" {
		parameters.AkeylessAccessType = os.Getenv(AkeylessAccessType)
	}

	if parameters.AkeylessAccessID == "" {
		parameters.AkeylessAccessID = os.Getenv(AkeylessAccessID)
	}

	if parameters.AkeylessAccessKey == "" {
		parameters.AkeylessAccessKey = os.Getenv(AkeylessAccessKey)
	}

	if parameters.AkeylessAzureObjectID == "" {
		parameters.AkeylessAzureObjectID = os.Getenv(AkeylessAzureObjectID)
	}

	if parameters.AkeylessGCPAudience == "" {
		parameters.AkeylessGCPAudience = os.Getenv(AkeylessGCPAudience)
	}

	if parameters.AkeylessUIDInitToken == "" {
		parameters.AkeylessUIDInitToken = os.Getenv(AkeylessUIDInitToken)
	}

	// Set default values.
	if parameters.VaultAddress == "" {
		parameters.VaultAddress = defaultVaultAddress
	}

	if parameters.VaultKubernetesMountPath == "" {
		parameters.VaultKubernetesMountPath = defaultVaultKubernetesMountPath
	}

	return parameters, nil
}

func (c *Config) UsingAccessKey() bool {
	return accessType(c.AkeylessAccessType) == AccessKey
}

func (c *Config) UsingAWS() bool {
	return accessType(c.AkeylessAccessType) == AWSIAM
}

func (c *Config) UsingAzure() bool {
	return accessType(c.AkeylessAccessType) == AzureAD
}

func (c *Config) UsingGCP() bool {
	return accessType(c.AkeylessAccessType) == GCP
}

func (c *Config) UsingUID() bool {
	return accessType(c.AkeylessAccessType) == UniversalIdentity
}

func (c *Config) validate() error {
	// Some basic validation checks.
	if c.TargetPath == "" {
		return errors.New("missing target path field")
	}
	if c.Parameters.VaultRoleName == "" {
		return errors.New("missing 'roleName' in SecretProviderClass definition")
	}
	if len(c.Parameters.Secrets) == 0 {
		return errors.New("no secrets configured - the provider will not read any secret material")
	}

	return nil
}

func createClient(vaultAddress string) *akeyless.V2ApiService {
	cfg := &akeyless.Configuration{
		Servers: []akeyless.ServerConfiguration{
			{
				URL: vaultAddress,
			},
		},
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   55 * time.Second,
					KeepAlive: 55 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   30 * time.Second,
				ExpectContinueTimeout: 30 * time.Second,
				// the total limit is bounded per host (MaxIdleConnsPerHost)
				// MaxIdleConns: 0,
				MaxIdleConnsPerHost: 100,
				MaxConnsPerHost:     200,
			},
			Timeout: 55 * time.Second,
		},
	}
	return akeyless.NewAPIClient(cfg).V2Api
}

func (c *Config) detectAccessType(aklClient *akeyless.V2ApiService) accessType {
	if c.AkeylessAccessID == "" {
		return ""
	}

	log.Printf("trying to detect privileged credentials for %v", c.AkeylessAccessID)

	if err := c.authWithAccessKey(context.Background(), aklClient); err == nil {
		return AccessKey
	}

	if err := c.authWithAWS(context.Background(), aklClient); err == nil {
		return AWSIAM
	}

	if err := c.authWithAzure(context.Background(), aklClient); err == nil {
		return AzureAD
	}

	if err := c.authWithGCP(context.Background(), aklClient); err == nil {
		return GCP
	}

	setAuthToken(c.AkeylessUIDInitToken)

	if err := c.rotateUIDToken(context.Background(), aklClient); err == nil {
		return UniversalIdentity
	}

	return ""
}
