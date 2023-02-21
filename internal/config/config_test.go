package config

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	objects      = "-\n  secretPath: \"/foo/bar\"\n  fileName: \"bar1\""
	certsSPCYaml = `apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: akeyless-vault
spec:
  provider: akeyless
  parameters:
    objects: |
      - fileName: "secret1"
        secretPath: "/F1/F2/secret1"
        secretType: "StaticSecret"
        secretArgs:
          foo: "bar"          
      - fileName: "secret2"
        secretPath: "/secret2"
`
	defaultAkeylessGatewayURL       = "http://127.0.0.1:18888"
	defaultVaultKubernetesMountPath = "kubernetes"
)

func TestParseParametersFromYaml(t *testing.T) {
	// Test starts with a minimal simulation of the processing the driver does with each SecretProviderClass yaml.
	var secretProviderClass struct {
		Spec struct {
			Parameters map[string]string `yaml:"parameters"`
		} `yaml:"spec"`
	}
	err := yaml.Unmarshal([]byte(certsSPCYaml), &secretProviderClass)
	require.NoError(t, err)

	paramsBytes, err := json.Marshal(secretProviderClass.Spec.Parameters)
	require.NoError(t, err)

	// This is now the form the provider receives the data in.
	params, err := parseParameters("", string(paramsBytes), defaultAkeylessGatewayURL, defaultVaultKubernetesMountPath)
	require.NoError(t, err)

	require.Equal(t, Parameters{
		AkeylessGatewayURL:       defaultAkeylessGatewayURL,
		VaultKubernetesMountPath: defaultVaultKubernetesMountPath,
		AkeylessAccessType:       "access_key",
		Secrets: []Secret{
			{
				FileName:   "secret1",
				SecretPath: "/F1/F2/secret1",
				SecretType: "StaticSecret",
				SecretArgs: map[string]interface{}{
					"foo": "bar",
				},
			},
			{
				FileName:   "secret2",
				SecretPath: "/secret2",
			},
		},
	}, params)
}

func TestParseParameters(t *testing.T) {
	// This file's contents are copied directly from a driver mount request.
	parametersStr, err := ioutil.ReadFile(filepath.Join("testdata", "example-params-string.txt"))
	require.NoError(t, err)
	actual, err := parseParameters("", string(parametersStr), defaultAkeylessGatewayURL, defaultVaultKubernetesMountPath)
	require.NoError(t, err)
	expected := Parameters{
		AkeylessGatewayURL: "https://vault.akeyless.io",
		AkeylessAccessType: "access_key",
		Secrets: []Secret{
			{"bar1", "/foo/bar", "", nil},
			{"bar2", "/bar2", "", nil},
		},
		VaultKubernetesMountPath: defaultVaultKubernetesMountPath,
		PodInfo: PodInfo{
			Name:               "nginx-secrets-store-inline",
			UID:                "9aeb260f-d64a-426c-9872-95b6bab37e00",
			Namespace:          "test",
			ServiceAccountName: "default",
		},
	}
	require.Equal(t, expected, actual)
}

func TestParseConfig(t *testing.T) {
	const targetPath = "/some/path"
	defaultParams := Parameters{
		AkeylessGatewayURL:       defaultAkeylessGatewayURL,
		VaultKubernetesMountPath: defaultVaultKubernetesMountPath,
		AkeylessAccessType:       "access_key",
	}
	for _, tc := range []struct {
		name       string
		targetPath string
		parameters map[string]string
		expected   Config
	}{
		{
			name:       "defaults",
			targetPath: targetPath,
			parameters: map[string]string{
				"akeylessAccessType": "access_key",
				"objects":            objects,
			},
			expected: Config{
				TargetPath:     targetPath,
				FilePermission: 420,
				Parameters: func() Parameters {
					expected := defaultParams
					expected.Secrets = []Secret{
						{"bar1", "/foo/bar", "", nil},
					}
					return expected
				}(),
			},
		},
		{
			name:       "non-defaults can be set",
			targetPath: targetPath,
			parameters: map[string]string{
				"akeylessAccessType":           "aws",
				"akeylessGatewayURL":           "my-vault-address",
				"vaultKubernetesMountPath":     "my-mount-path",
				"KubernetesServiceAccountPath": "my-account-path",
				"objects":                      objects,
			},
			expected: Config{
				TargetPath:     targetPath,
				FilePermission: 420,
				Parameters: func() Parameters {
					expected := defaultParams
					expected.AkeylessAccessType = "aws"
					expected.AkeylessGatewayURL = "my-vault-address"
					expected.VaultKubernetesMountPath = "my-mount-path"
					expected.Secrets = []Secret{
						{"bar1", "/foo/bar", "", nil},
					}
					return expected
				}(),
			},
		},
	} {
		parametersStr, err := json.Marshal(tc.parameters)
		require.NoError(t, err)
		cfg, err := Parse("", string(parametersStr), tc.targetPath, "420", defaultAkeylessGatewayURL, defaultVaultKubernetesMountPath)
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.expected, cfg)
	}
}

func TestParseConfig_Errors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		targetPath string
		parameters map[string]string
	}{
		{
			parameters: map[string]string{
				"vaultSkipTLSVerify": "true",
				"objects":            objects,
			},
		},
		{
			name: "no secrets configured",
			parameters: map[string]string{
				"vaultSkipTLSVerify": "true",
				"objects":            "",
			},
		},
	} {
		_, err := json.Marshal(tc.parameters)
		require.NoError(t, err)
	}
}

func TestValidateConfig(t *testing.T) {
	minimumValid := Config{
		TargetPath: "a",
		Parameters: Parameters{
			AkeylessGatewayURL: defaultAkeylessGatewayURL,
			Secrets:            []Secret{{}},
		},
	}
	for _, tc := range []struct {
		name     string
		cfg      Config
		cfgValid bool
	}{
		{
			name:     "minimum valid",
			cfgValid: true,
			cfg:      minimumValid,
		},
		{
			name: "No role name",
			cfg: func() Config {
				cfg := minimumValid
				return cfg
			}(),
		},
		{
			name: "No target path",
			cfg: func() Config {
				cfg := minimumValid
				cfg.TargetPath = ""
				return cfg
			}(),
		},
		{
			name: "No secrets configured",
			cfg: func() Config {
				cfg := minimumValid
				cfg.Secrets = []Secret{}
				return cfg
			}(),
		},
	} {
		err := tc.cfg.validate()
		if tc.cfgValid {
			require.NoError(t, err, tc.name)
		} else {
			require.Error(t, err, tc.name)
		}
	}
}
