GO_VERSION = $(shell go mod edit -json | jq -r .Go)
DATE = $(shell date -u +%Y%m%d.%H%M%S)
IMAGE_NAME = "docker.io/akeyless/akeyless-csi-provider"
VERSION ?= 0.0.0

ifeq ($(VERSION), 0.0.0)
	TAG = "latest"
else
    TAG = v$(VERSION)
endif

VERSION_FLAG = akeyless.io/akeyless-csi-provider/internal/version.Version=$(VERSION)
DATE_FLAG = akeyless.io/akeyless-csi-provider/go/src/internal/version.BuildDate=$(DATE)
LDFLAGS = "-w -s -X $(VERSION_FLAG) -X $(DATE_FLAG)"

build:
	docker build --build-arg="GO_VERSION=$(GO_VERSION)" --build-arg=LDFLAGS=$(LDFLAGS) -t $(IMAGE_NAME):$(TAG) .

push:
ifeq ($(VERSION), 0.0.0)
	@echo can only push image if version is set 
	exit 1
endif
	docker push $(IMAGE_NAME):$(TAG)

all: build push