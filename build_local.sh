#!/bin/bash
set -e
function usage() {
	cat <<EOF
Usage: $0
    [--version]

required arguments:
    --version      Specify the version for image
EOF
	exit 1
}


function handle_parameters() {
    version=""
    until [ -z $1 ]; do
        case $1 in
        --version )
            version="$2"
            shift
            ;;
        esac
        shift
    done

    if [ "$version" == "" ]; then
        echo "version is missing"
        usage
    fi
}


# ========== Start main script ============

handle_parameters $*

image="akeyless/akeyless-csi-provider"
docker_repo="docker.io"
arc='amd64'
os='linux'
versionVar="akeyless.io/akeyless-csi-provider/internal/version.Version=$version"
buildDateVar="akeyless.io/akeyless-csi-provider/go/src/internal/version.BuildDate=$(date -u +%Y%m%d.%H%M%S)"
goVer="github.com/akeylesslabs/akeyless-csi-provider/internal/version.GoVersion=$(go version)"

GOOS=$os GOARCH=$arc CGO_ENABLED=0 go build \
		-ldflags "-w -s -X $versionVar -X $buildDateVar" \
		-o dist/ \
		.

echo "Building $image:latest docker image"
eval $(minikube docker-env)
docker build --build-arg PRODUCT_VERSION="$version" --load -t $image:latest .

docker tag "$image":latest "$docker_repo/$image":"$version"
rm -rf dist/