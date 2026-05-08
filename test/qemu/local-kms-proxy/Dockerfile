FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /local-kms-proxy .

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /local-kms-proxy /usr/local/bin/
ENTRYPOINT ["local-kms-proxy"]
