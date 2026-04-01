FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY v2/go.mod v2/go.sum ./v2/
COPY gen/go/ ./gen/go/
WORKDIR /app/v2
RUN go mod download
COPY v2/ ./
RUN CGO_ENABLED=0 go build -o /gateway ./gateway/cmd/

FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl
COPY --from=builder /gateway /usr/local/bin/gateway
EXPOSE 8090
USER nobody
ENTRYPOINT ["gateway"]
