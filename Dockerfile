## builder
FROM rust:1.75-bookworm AS builder

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
FROM golang as dnstap
RUN go install github.com/dnstap/golang-dnstap/dnstap@v0.4.0

## runtime
FROM debian:12
RUN apt update && apt install -y dnsdist certbot

WORKDIR /dnsdist-acme

# copy binary
COPY --from=builder /code/dnsdist-acme/target/release/dnsdist-acme /usr/local/bin/dnsdist-acme
COPY --from=dnstap /go/bin/dnstap /usr/bin/.

RUN mkdir -p certs html/.well-known
COPY dnsdist.conf dnsdist.conf

# set entrypoint
ENTRYPOINT ["/usr/local/bin/dnsdist-acme"]

EXPOSE 53/tcp 53/udp 80 8080 8443
