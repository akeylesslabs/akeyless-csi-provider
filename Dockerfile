FROM alpine:3.15.0 AS default

ARG PRODUCT_VERSION
ARG PRODUCT_NAME=akeyless-csi-provider

LABEL version=$PRODUCT_VERSION


COPY dist/akeyless-csi-provider /bin/
ENTRYPOINT [ "/bin/akeyless-csi-provider" ]
