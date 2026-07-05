#!/bin/bash
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-akeyless-csi-local}"
NAMESPACE="${NAMESPACE:-alexey}"
VERSION="${VERSION:-0.5.1}"
IMAGE="docker.io/akeyless/akeyless-csi-provider:${VERSION}"

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    echo "Creating kind cluster $CLUSTER_NAME..."
    kind create cluster --name "$CLUSTER_NAME"
fi

kubectl config use-context "kind-${CLUSTER_NAME}"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

./build.sh --version "$VERSION" --local

echo "Loading image into kind..."
kind load docker-image "$IMAGE" --name "$CLUSTER_NAME"

helm repo add akeyless https://akeylesslabs.github.io/helm-charts 2>/dev/null || true
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts 2>/dev/null || true
helm repo update

if ! helm status csi-secrets-store -n "$NAMESPACE" >/dev/null 2>&1; then
    helm install csi-secrets-store secrets-store-csi-driver/secrets-store-csi-driver \
        -n "$NAMESPACE" \
        --set syncSecret.enabled=true
fi

helm upgrade --install akeyless-csi akeyless/akeyless-csi-provider \
    -n "$NAMESPACE" \
    --set csi.image.repository=akeyless/akeyless-csi-provider \
    --set csi.image.tag="$VERSION" \
    --set csi.image.pullPolicy=Never

echo "Waiting for provider pods..."
kubectl wait --for=condition=ready pod -n "$NAMESPACE" -l app.kubernetes.io/name=akeyless-csi-provider-csi-provider --timeout=120s
kubectl get pods -n "$NAMESPACE"
