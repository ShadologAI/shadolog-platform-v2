FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY v2/go.mod v2/go.sum ./v2/
COPY gen/go/ ./gen/go/
WORKDIR /app/v2
RUN go mod download
COPY v2/ ./
COPY detections/rules/ /app/detections/rules/
RUN CGO_ENABLED=0 go build -o /brain ./brain/cmd/

FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl
COPY --from=builder /brain /usr/local/bin/brain
COPY --from=builder /app/detections/rules/ /app/detections/rules/
EXPOSE 8091
USER nobody
ENTRYPOINT ["brain"]
