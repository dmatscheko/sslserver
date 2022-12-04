# A web server that serves static files over HTTPS

A web server that serves static files over HTTPS, manages TLS certificates, has security measures for Linux, and can stop when a certificate expires.

## Description
### General features

- Serves static files from the subdirectory `./static`.
- Reads each file only once and caches it in memory.
- Serves the static files via HTTPS.
- Redirects all HTTP requests to HTTPS.

### TLS certificate management

- Automatically fetches TLS certificates from Let's Encrypt.
- Creates a self signed certificate if Let's Encrypt is unreachable or denies a certificate for an white listed domain.
- You need to configure the white listed domains.

### Security measures

- If compiled and executed on Linux, drops all privileges and jails itself in the `./jail` subdirectory.

### Timer and shutdown

- Loads all SSL certificates at startup and retrieves their expiration time.
- If configured to do so, the web server terminates a configured duration before the first SSL certificate expires.
- In this case, you have to restart the server with a script, it then creates a new Let's Encrypt certificate.

## Build

    go run .

or

    go build .
    ./sslserver

## Configuration

At the moment, you have to configure the server in the `config.go` and recompile.
