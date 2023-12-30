# dnstap
FROM golang:alpine as dnstap
RUN go install github.com/dnstap/golang-dnstap/dnstap@v0.4.0

# rust builder
FROM rust:1.75-alpine as rust-builder



# dnsdist
FROM alpine:latest
RUN apk add dnsdist certbot bash

COPY --from=dnstap /go/bin/dnstap /usr/bin/.
COPY dnsdist.conf /etc/dnsdist.conf
COPY entrypoint.sh /entrypoint.sh
RUN mkdir -p /data/certs

EXPOSE 53/tcp 53/udp 80 443
ENTRYPOINT /entrypoint.sh
