# dnsdist-acme

A DNS Proxy Server powered by dnsdist with automatic TLS cert management

## Introduction

[dnsdist](https://dnsdist.org/) is a highly DNS-, DoS- and abuse-aware loadbalancer.
Its goal in life is to route traffic to the best server, delivering top performance to legitimate users while shunting or blocking abusive traffic.

In order to make it easier to deploy onto a live environment and easier to debug, I decided to combine dnsdist with several components:

- [dnsdist](https://dnsdist.org/) - dns load balancer. The current config enables handling DNS53, DoT, DoH protocols
- [certbot](https://certbot.eff.org/) - automatically handles obtaining an TLS cert from LetsEncrypt, for use in DoT and DoH protocols
- [golang-dnstap](https://github.com/dnstap/golang-dnstap) - captures query logs from dnsdist and saves it to a file
- [rust] - main binary to orchestrate the different components. Also serves a web page for viewing the dns logs from the origin ip address

At the moment, this project is available as a Docker container, with all the required components built-in.
It is currently only available for Docker architecture linux-x86_64.
If you want to run this on a Raspberry PI, I will need to build and push this project Docker images for Armv6 and Armv7 architectures.
I intend to provide this in the near future.

This project is currently used in my [Adblock DNS Server](https://github.com/ragibkl/adblock-dns-server) to serve as the DNS ingress point.
It handles the incoming DNS53, DoT, DoH traffic and routes it to the main [Bancuh Adblock DNS](https://github.com/ragibkl/bancuh-dns).

## Getting Started

The simplest way to see it in action is to run it using a Docker Compose file.
This example spins up the dns proxy and routes all traffic to Google's DNS at `8.8.8.8`.
Run it with `docker compose up -d`.

```yaml
version: "3"

services:
  dnsdist:
    image: ragibkl/dnsdist-acme
    restart: always
    environment:
      - PORT=53
      - BACKEND=8.8.8.8:53
      - TLS_ENABLED=false
      - TLS_DOMAIN=dns.yourdomain.com
      - TLS_EMAIL=user@example.com
    network_mode: host
```

## Enabling DoH and DoT protocols

In order to enable DoH and DoT protocols, you need to run this project on a server with a public IP address.
Additionally, you also need to have a FQDN domain record that resolves to the IP address of your server.
Probably something in the form of `dns.yourdomain.com`

Update the following variables and rerun `docker compose up -d`

```yaml
- TLS_ENABLED=true
- TLS_DOMAIN=dns.yourdomain.com # Put your fqdn here
- TLS_EMAIL=user@example.com    # Put a valid email here
```

With tls enabled, the server will obtain a TLS cert from LetsEncrypt, keep it updated, and use it to serve DNS traffic over DoH and DoT.

## Viewing Logs for Troubleshooting

A feature of this project is the ability to view DNS query logs for the originating IP.
Logs are cleaned up every 10 minutes.

Logs pages:

- <http://server-ip-address:8080/logs>
- <http://dns.yourdomain.com:8080/logs>
- <https://dns.yourdomain.com:8443/logs> # only with tls enabled

## Using it with other DNS projects

This dns project should be used in conjuction with another DNS service.
You can follow the instructions at [Adblock DNS Server - Getting Started](https://github.com/ragibkl/adblock-dns-server#getting-started) to see how it can be used with my [Bancuh Adblock DNS](https://github.com/ragibkl/bancuh-dns) project.

In theory, you should be able to use it together with other Adblock DNS server such as [PiHole](https://hub.docker.com/r/pihole/pihole).
The following example has not been tested, but you should be able to tinker it to work.

```yaml
version: "3"

# Minimal setup. More info at https://github.com/pi-hole/docker-pi-hole/ and https://docs.pi-hole.net/
services:
  pihole:
    image: pihole/pihole:latest
    ports:
      - "1153:53/tcp" # using a different port
      - "1153:53/udp"
    environment:
      TZ: 'America/Chicago'
    volumes:
      - './etc-pihole:/etc/pihole'
      - './etc-dnsmasq.d:/etc/dnsmasq.d'
    restart: unless-stopped

  dnsdist:
    image: ragibkl/dnsdist-acme
    restart: always
    environment:
      - PORT=53
      - BACKEND=127.0.0.1:1153 # point to pihole backend
      - TLS_ENABLED=false
      - TLS_DOMAIN=dns.example.com
      - TLS_EMAIL=user@example.com
    network_mode: host
```
