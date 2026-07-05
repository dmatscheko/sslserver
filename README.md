# A static web server with HTTPS, automatic certificates and a process jail

Serves static files for multiple domains over HTTPS with automatic Let's
Encrypt certificates. On Linux, the serving process locks itself into a
chroot jail with no privileges; certificate renewal keeps working from
inside the jail.

## Features

- **Virtual hosting**: every subdirectory of the web root is served as one
  domain (`www_static/example.com/…` → `https://example.com/…`).
- **Automatic TLS**: Let's Encrypt certificates (http-01 and tls-alpn-01
  challenges) with automatic renewal, for every domain directory found in
  the web root. Domains listed in `self-signed-domains` — and any domain
  Let's Encrypt fails for — get a self-signed certificate instead.
- **In-memory cache**: all files up to `max-cacheable-file-size` are read
  once at startup and served from memory.
- **Privilege separation**: the parent process keeps the only disk access
  (certificate cache, log file) and supervises the child, which binds ports
  80/443, then chroots, drops to the first of `www`/`www-data`/`_www`/
  `nobody` that exists, and clears its environment (Linux, macOS and the
  BSDs, when started as root; on Windows only the working directory and
  environment are restricted). The child reaches the certificate store
  through a pipe RPC, so renewed certificates are persisted even though the
  child has no file system.
  - `serve-files-not-in-cache: true` — the child jails itself *into the web
    root* and keeps read-only access to it, so files larger than the cache
    limit are served from disk.
  - `serve-files-not-in-cache: false` — the child jails itself into an empty
    directory and loses disk access completely; only cached files are served.
- HTTP on port 80 answers ACME challenges and redirects everything else to
  HTTPS. HTTP/2, TLS 1.2+ with the Mozilla-intermediate cipher suites, and
  configurable security headers. Directory URLs serve their `index.html`
  (with a canonical redirect), dot files are never served, unknown `Host`
  headers get a 404.
- Logging to stdout and a log file with built-in rotation (5 MB, 3 old files
  kept) and age-based cleanup of rotated-out files (`log-max-age`).
  `SIGINT`/`SIGTERM` shut the server down gracefully.

## Build and run

    CGO_ENABLED=0 go build -o sslserver .

The binary is fully static (no cgo). Run it as root so it can bind the
privileged ports and enter the jail:

    sudo ./sslserver

On the first start a `config.yml` with all defaults is created **next to the
executable**. A different config file can be given with:

    ./sslserver -config /etc/sslserver/config.yml

Relative paths inside the config are resolved against the config file's
directory, so the working directory never matters. Without root (and on
non-Linux systems) the server runs without the jail and prints a warning —
useful for development with unprivileged ports.

## Configuration

| Key | Default | Meaning |
| --- | --- | --- |
| `web-root-directory` | `www_static` | One subdirectory per domain. All contents are made read-only (`a=r`/`a=rx`) at startup. |
| `certificate-cache-directory` | `certcache` | Let's Encrypt storage, used by the parent only. Must be outside the web root. |
| `acme-email` | `""` | E-mail for the Let's Encrypt account. |
| `http-addr`, `https-addr` | `:http`, `:https` | Listen addresses. |
| `self-signed-domains` | `[localhost, 127.0.0.1]` | Domains/IPs served with a self-signed certificate instead of Let's Encrypt. |
| `server-name` | `dma-srv` | `Server` response header (`""` = none). |
| `http-headers` | security defaults | Response headers, merged over the defaults (HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`). Set a value to `""` to disable it. |
| `certificate-expiry-refresh-threshold` | `48h` | Renew certificates this long before they expire. |
| `max-request-timeout`, `max-response-timeout`, `max-idle-timeout` | `15s`, `60s`, `60s` | HTTP server timeouts. |
| `serve-files-not-in-cache` | `true` | Keep read-only disk access inside the jail (see above). |
| `max-cacheable-file-size` | `1048576` | Files up to this size are cached in memory at startup. |
| `log-requests` | `true` | Log every request. |
| `log-file` | `server.log` | Written by the parent, rotated at 5 MB (`""` = stdout only). |
| `log-max-age` | `720h` (30 days) | Delete rotated-out log files older than this (`0` = keep them until the rotation count replaces them). |

Content updates require a restart: the cache is filled once at startup, and
the jailed child intentionally cannot see changed files.

## Development

    go vet .
    go test .
