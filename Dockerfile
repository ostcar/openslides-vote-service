FROM golang:1.19.2-alpine as base
WORKDIR /root/

RUN apk add git

COPY go.mod go.sum ./
RUN go mod download

COPY cmd cmd
COPY internal internal

# Build service in seperate stage.
FROM base as builder
RUN CGO_ENABLED=0 go build ./cmd/vote
RUN CGO_ENABLED=0 go build ./cmd/healthcheck


# Test build.
FROM base as testing

RUN apk add build-base

CMD go vet ./... && go test ./...


# Development build.
FROM base as development

RUN ["go", "install", "github.com/githubnemo/CompileDaemon@latest"]
EXPOSE 9012
ENV AUTH ticket

CMD CompileDaemon -log-prefix=false -build="go build ./cmd/vote" -command="./vote"


# Productive build
FROM scratch

LABEL org.opencontainers.image.title="OpenSlides Vote Service"
LABEL org.opencontainers.image.description="The OpenSlides Vote Service handles the votes for electronic polls."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/OpenSlides/openslides-vote-service"

COPY --from=builder /root/vote .
COPY --from=builder /root/healthcheck .
EXPOSE 9013
ENV AUTH ticket

ENTRYPOINT ["/vote"]
HEALTHCHECK CMD ["/healthcheck"]
