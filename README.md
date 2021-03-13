# Self-Signed Server

[![Docker](https://badgen.net/badge/jnovack/self-signed-server/blue?icon=docker)](https://hub.docker.com/r/jnovack/self-signed-server)
[![Github](https://badgen.net/badge/jnovack/self-signed-server/purple?icon=github)](https://github.com/jnovack/self-signed-server)

**self-signed-server** is a quick and simple HTTPS server designed for testing.
It is specifically meant to test self-signed certificates behind load-balancers
such as nginx or haproxy to validate configuration or prove an environment.

Each image generates it's own root, intermediate, and leaf certificate.  The
root certificate is available for download over HTTP while a "whoami"-like
response is served over HTTPS to prove you are loadbalancing properly.

In typical usage, the loadbalancer reverse proxy in front of this server SHOULD
NOT care about the self-signed nature of the backend server and MUST present
its own valid certificate to the end-user.

## Quick Start

```yml
version: '3.8'

services:
  loadbalancer:
    ## haproxy/nginx/apache/etc ##
    depends_on:
      - dummy
    ports:
      - 8080:80
      - 8443:443
    restart: always

  dummy:
    image: jnovack/self-signed-server:latest
    deploy:
      replicas: 3
```

## Notes

The key words “MUST”, “MUST NOT”, “REQUIRED”, “SHALL”, “SHALL NOT”, “SHOULD”,
“SHOULD NOT”, “RECOMMENDED”, “MAY”, and “OPTIONAL” in this document are to be
interpreted as described in [RFC 2119](http://tools.ietf.org/html/rfc2119).
