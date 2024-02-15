# Akeyless Provider for Secret Store CSI Driver

[Akeyless](https://www.akeyless.io/) provider for the [Secrets Store CSI driver](https://github.com/kubernetes-sigs/secrets-store-csi-driver) allows you to get secrets stored in Akeyless and use the Secrets Store CSI driver interface to mount them into Kubernetes pods.

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
helm repo add akeyless https://akeylesslabs.github.io/helm-charts
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
