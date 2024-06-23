ARG GO_VERSION
FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /src

COPY . .

ARG ARC="amd64"
ARG LDFLAGS=""
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$ARC go build -ldflags "${LDFLAGS}" -a -installsuffix cgo -o akeyless-csi-provider .

# Final stage
FROM alpine:3.20.1

ARG PRODUCT_VERSION
ARG PRODUCT_NAME=akeyless-csi-provider

LABEL version=$PRODUCT_VERSION

RUN addgroup -S nonroot && adduser -S nonroot -G nonroot

COPY --from=builder --chown=nonroot:nonroot --chmod=755 /src/akeyless-csi-provider /app/akeyless-csi-provider

USER nonroot

ENTRYPOINT [ "/app/akeyless-csi-provider" ]
