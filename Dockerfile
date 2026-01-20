FROM golang:1.24-alpine AS builder

# Install build-essential and other necessary packages
RUN apk add --no-cache build-base

WORKDIR /app
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o shutter-api

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/shutter-api .
COPY migrations ./migrations

EXPOSE 5000

CMD ["./shutter-api"]