## builder
FROM alpine as builder
RUN apk add rust cargo

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
FROM alpine as dnstap
RUN apk add go
RUN go install github.com/dnstap/golang-dnstap/dnstap@v0.4.0

## runtime
FROM alpine

WORKDIR /dnsdist-acme

# install runtime dependencies
RUN apk add gcompat certbot dnsdist

# copy binary
COPY --from=builder /code/dnsdist-acme/target/release/dnsdist-acme /usr/local/bin/dnsdist-acme
COPY --from=dnstap /root/go/bin/dnstap /usr/bin/.

RUN mkdir -p certs html/.well-known
COPY dnsdist.conf dnsdist.conf

# set entrypoint
ENTRYPOINT ["/usr/local/bin/dnsdist-acme"]

EXPOSE 53/tcp 53/udp 80 8080 8443
