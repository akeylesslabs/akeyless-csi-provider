FROM alpine:3.23 AS default

RUN apk --no-cache upgrade

ARG PRODUCT_VERSION
ARG PRODUCT_NAME=akeyless-csi-provider

LABEL version=$PRODUCT_VERSION


COPY dist/akeyless-csi-provider /bin/
ENTRYPOINT [ "/bin/akeyless-csi-provider" ]
