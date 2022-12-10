FROM golang:1.19.4-alpine as base
WORKDIR /root/

RUN apk add git

COPY go.mod go.sum ./
RUN go mod download

COPY main.go main.go
COPY internal internal

# Build service in seperate stage.
FROM base as builder
RUN CGO_ENABLED=0 go build


# Test build.
FROM base as testing

RUN apk add build-base

CMD go vet ./... && go test ./...


# Development build.
FROM base as development

RUN ["go", "install", "github.com/githubnemo/CompileDaemon@latest"]
EXPOSE 9012

CMD CompileDaemon -log-prefix=false -build="go build" -command="./openslides-vote-service"


# Productive build
FROM scratch

LABEL org.opencontainers.image.title="OpenSlides Vote Service"
LABEL org.opencontainers.image.description="The OpenSlides Vote Service handles the votes for electronic polls."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/OpenSlides/openslides-vote-service"

COPY --from=builder /root/openslides-vote-service .
EXPOSE 9013

ENTRYPOINT ["/openslides-vote-service"]
HEALTHCHECK CMD ["/openslides-vote-service", "health"]
