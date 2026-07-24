FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
LABEL maintainer="nekohasekai <contact-git@sekai.icu>"
COPY . /go/src/github.com/sagernet/serenity
WORKDIR /go/src/github.com/sagernet/serenity
ARG TARGETOS TARGETARCH
ARG GOPROXY=""
ENV GOPROXY ${GOPROXY}
ENV CGO_ENABLED=0
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH
RUN apk add --no-cache git build-base
RUN --mount=type=secret,id=oixcloud_hmac_key \
    set -e \
    && export COMMIT=$(git rev-parse --short HEAD) \
    && export VERSION=$(go run github.com/sagernet/sing-box/cmd/internal/read_tag@latest) \
    && if [ -f /run/secrets/oixcloud_hmac_key ]; then OIXCLOUD_HMAC_KEY=$(cat /run/secrets/oixcloud_hmac_key); else OIXCLOUD_HMAC_KEY=; fi \
    && go build -v -trimpath \
        -o /go/bin/serenity \
        -ldflags "-X github.com/sagernet/serenity/constant.Version=$VERSION -X github.com/sagernet/serenity/constant.OIXCloudSubscriptionHMACKey=$OIXCLOUD_HMAC_KEY -s -w -buildid=" \
        ./cmd/serenity
FROM --platform=$TARGETPLATFORM alpine AS dist
LABEL maintainer="nekohasekai <contact-git@sekai.icu>"
RUN set -ex \
    && apk upgrade \
    && apk add bash tzdata ca-certificates \
    && rm -rf /var/cache/apk/*
COPY --from=builder /go/bin/serenity /usr/local/bin/serenity
ENTRYPOINT ["serenity"]
