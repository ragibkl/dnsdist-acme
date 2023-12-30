## builder
FROM rust:1.75-alpine AS builder

WORKDIR /code/dnsdist-acme

# setup build dependencies
RUN cargo init .
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release
RUN rm -rf ./src/

# copy code files
COPY /src/ ./src/

# build code
RUN touch ./src/main.rs
RUN cargo build --release

## dnstap
FROM golang:alpine as dnstap
RUN go install github.com/dnstap/golang-dnstap/dnstap@v0.4.0

## runtime
FROM alpine:latest
RUN apk add dnsdist certbot bash

# copy binary
COPY --from=dnstap /go/bin/dnstap /usr/bin/.
COPY --from=builder /code/dnsdist-acme/target/release/dnsdist-acme /usr/local/bin/dnsdist-acme

COPY dnsdist.conf dnsdist.conf

# set entrypoint
ENTRYPOINT ["/usr/local/bin/dnsdist-acme"]

EXPOSE 53/tcp 53/udp 80 8080 8443
