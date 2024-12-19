FROM golang:1.22-alpine AS builder

# Install build-essential and other necessary packages
RUN apk add --no-cache build-base

WORKDIR /app
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o shutter-service-api

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/shutter-service-api .

EXPOSE 5000

CMD ["./shutter-service-api"]
