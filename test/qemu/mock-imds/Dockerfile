FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download || true
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /mock-imds .

FROM alpine:latest
COPY --from=builder /mock-imds /usr/local/bin/
ENTRYPOINT ["mock-imds"]
