# Akeyless Provider for Secret Store CSI Driver

[Akeyless](https://www.akeyless.io/) provider for the [Secrets Store CSI driver](https://github.com/kubernetes-sigs/secrets-store-csi-driver) allows you to get secrets stored in Akeyless and use the Secrets Store CSI driver interface to mount them into Kubernetes pods.

## Gateway allowlist

Before authenticating, the provider authorizes `akeylessGatewayURL` against operator configuration (not SPC-controlled allowlists):

1. `AKEYLESS_URL` / `--akeyless-address` (default trusted gateway)
2. Extra base URLs in `AKEYLESS_ALLOWED_GATEWAY_URLS` (comma-separated)

Unlisted gateways are rejected so a tenant SPC cannot redirect provider credentials to an attacker-controlled endpoint. Prefer HTTPS.

## Authentication

Supported `akeylessAccessType` values:

| Type | Notes |
| --- | --- |
| `access_key` | API key. SPC/`nodePublishSecretRef` value wins if set; otherwise `AKEYLESS_ACCESS_KEY` / `CREDENTIALS`. Prefer env-only (omit from SPC). |
| `k8s` | Kubernetes auth via Gateway config (`akeylessK8sAuthConfigName`). |
| `jwt` / `oauth2` | [OAuth2.0/JWT](https://docs.akeyless.io/docs/auth-with-oauth-jwt) auth method. |
| `aws_iam` | AWS IAM cloud identity. |
| `azure_ad` | Azure AD / Workload Identity. |
| `gcp` | GCP workload identity (`akeylessGCPAudience`). |
| `universal_identity` | Universal Identity init token. |

If `akeylessAccessType` is omitted, the provider auto-detects among access key / cloud / k8s / jwt / universal identity (legacy behavior). JWT is only probed when a JWT was supplied via CSI secret or `AKEYLESS_JWT`.

### OAuth2.0 / JWT

Set `akeylessAccessType: jwt` (or `oauth2`) and the auth-method `akeylessAccessID`.

Token sources on each auth (first match wins):

1. CSI `nodePublishSecretRef` secret key `akeylessJWT` (this mount only; updated when the driver republishes)
2. Provider env `AKEYLESS_JWT`, only when this mount did not set `akeylessJWT` (one identity for every such mount on the node)

Do **not** fall back to the provider ServiceAccount token, and do **not** put the JWT in `SecretProviderClass` parameters (those are stored in etcd). Bind Access Role sub-claims to the ServiceAccount that owns the JWT in `akeylessJWT`. See `examples/example-jwt.yaml`.

## Installation

### Prerequisites

* Kubernetes 1.16+ for both the master and worker nodes (Linux-only)
* [Secrets store CSI driver](https://secrets-store-csi-driver.sigs.k8s.io/getting-started/installation.html) installed
* `TokenRequest` endpoint available, which requires setting the flags
  `--service-account-signing-key-file` and `--service-account-issuer` for
  `kube-apiserver`. Set by default from 1.20+ and earlier in most managed services.

### Using helm

The recommended installation method is via helm 3:

```bash
helm repo add akeylesshttps://akeylesslabs.github.io/helm-charts
helm install akeyless akeyless/akeyless-csi-provider
```

### Using yaml

You can also install using the deployment config in the `deployment` folder:

```bash
kubectl apply -f deployment/akeyless-csi-provider.yaml
```

## Troubleshooting

To troubleshoot issues with Akeyless CSI provider, look at logs from the CSI provider pod running on the same node as your application pod:

  ```bash
  kubectl get pods -o wide
  # find the Akeyless CSI provider pod running on the same node as your application pod

  kubectl logs akeyless-csi-provider-xxxxx
  ```
