## builder
FROM alpine:3.23 AS builder

WORKDIR /code/dnsdist-acme

# setup build dependencies
RUN apk add rust cargo build-base cmake perl
RUN cargo init .
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release
RUN rm -rf ./src/

# copy code files
COPY /src/ ./src/

# build code
RUN touch ./src/main.rs
RUN cargo build --release


## runtime
FROM alpine:3.23 AS runtime

WORKDIR /dnsdist-acme

# install runtime dependencies
# certbot is gone: ACME is handled in-process by rustls-acme.
RUN apk add gcompat dnsdist

# copy binary
COPY --from=builder /code/dnsdist-acme/target/release/dnsdist-acme /usr/local/bin/dnsdist-acme

RUN mkdir -p certs html/.well-known
COPY dnsdist.conf dnsdist.conf

# set entrypoint
ENTRYPOINT ["/usr/local/bin/dnsdist-acme"]

EXPOSE 53/tcp 53/udp 80 443 853 8080 8443
