FROM alpine:3.20.3 AS default

ARG TARGETARCH
ARG PRODUCT_VERSION
ARG PRODUCT_NAME=akeyless-csi-provider

LABEL version=$PRODUCT_VERSION

COPY dist/$TARGETARCH/akeyless-csi-provider /bin/
ENTRYPOINT [ "/bin/akeyless-csi-provider" ]
