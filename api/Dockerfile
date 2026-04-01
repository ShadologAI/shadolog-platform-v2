FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY v2/go.mod v2/go.sum ./v2/
COPY gen/go/ ./gen/go/
WORKDIR /app/v2
RUN go mod download
COPY v2/ ./
RUN CGO_ENABLED=0 go build -o /api ./api/cmd/

FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl
COPY --from=builder /api /usr/local/bin/api
COPY deploy/spicedb/schema.zed /app/deploy/spicedb/schema.zed
EXPOSE 8100
USER nobody
ENTRYPOINT ["api"]
