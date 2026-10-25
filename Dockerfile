FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gha-token-broker ./cmd/gha-token-broker

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/gha-token-broker /gha-token-broker
USER 65532:65532
ENV GOMEMLIMIT=40MiB GOMAXPROCS=1
EXPOSE 8080
ENTRYPOINT ["/gha-token-broker"]
