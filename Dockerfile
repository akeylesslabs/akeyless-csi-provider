FROM alpine:3.23 AS default

ARG PRODUCT_VERSION
ARG PRODUCT_NAME=akeyless-csi-provider

LABEL version=$PRODUCT_VERSION

# Refresh base packages so image rebuilds pick up Alpine security fixes
# (openssl/libcrypto3, zlib, musl) reported by Appsec ImageScan.
RUN apk --no-cache upgrade \
	&& apk --no-cache add --upgrade libcrypto3 libssl3 zlib musl musl-utils

COPY dist/akeyless-csi-provider /bin/
ENTRYPOINT [ "/bin/akeyless-csi-provider" ]
