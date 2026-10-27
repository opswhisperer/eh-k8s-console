# Static Go binary on distroless (includes CA roots, used to recognise public-CA sensor certs).
# Base images are pinned by digest; Dependabot proposes updates.
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/eh-k8s-console ./cmd/eh-k8s-console

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.title="eh-k8s-console" \
      org.opencontainers.image.description="Community web console for the ExtraHop Kubernetes integration (not affiliated with ExtraHop Networks)" \
      org.opencontainers.image.source="https://github.com/opswhisperer/eh-k8s-console" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/eh-k8s-console /eh-k8s-console
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /licenses/
USER 65532:65532
EXPOSE 8080 9090
ENTRYPOINT ["/eh-k8s-console"]
CMD ["serve", "-config", "/config/config.yaml"]
