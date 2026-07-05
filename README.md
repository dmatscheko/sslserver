# A static web server with HTTPS, automatic certificates and a process jail

Serves static files for multiple domains over HTTPS with automatic Let's
Encrypt certificates. The serving process locks itself into a chroot jail
without privileges; certificate renewal keeps working from inside the jail.

## Features

- **Virtual hosting**: every subdirectory of the web root is served as one
  domain (`www_static/example.com/…` → `https://example.com/…`).
- **Automatic TLS**: Let's Encrypt certificates (http-01 and tls-alpn-01
  challenges) with automatic renewal for every domain directory in the web
  root. Domains listed in `self-signed-domains` — and any domain Let's
  Encrypt fails for — get a self-signed certificate instead.
- **In-memory cache**: all files up to `max-cacheable-file-size` (and up to
  `max-total-cache-size` in total) are read once at startup and served from
  memory — with precompressed gzip variants and strong ETags, so most
  responses are either tiny (304) or compressed.
- **Privilege separation and a real jail** — see below.
- **Per-domain overrides** (`domains`): response headers per site, and
  `serve-http` to serve a site over plain HTTP instead of redirecting it.
- HTTP on port 80 answers ACME challenges and redirects everything else to
  HTTPS (except `serve-http` domains). HTTP/2, TLS 1.2+ with the
  Mozilla-intermediate cipher suites, configurable security headers, and a
  connection cap per listener.
- Logging to stdout and a rotated, age-pruned log file. `SIGINT`/`SIGTERM`
  shut the server down gracefully.

## How it works

The program runs as two processes started from the same binary.

The **parent** keeps the only permanent disk access: it stores certificates
in `certificate-cache-directory`, answers the child's certificate lookups
over a pipe RPC, and writes the log file. It forwards termination signals
to the child and exits when the child exits.

The **child** does all the network-facing work. At startup it:

1. reads the same config file as the parent,
2. binds the HTTP and HTTPS ports (one reason it must start as root),
3. makes the web root world-readable and read-only — files `0444`,
   directories `0555` — and transfers its ownership to root
   (`chown-web-root`),
4. reads every regular file up to `max-cacheable-file-size` into the
   in-memory cache; dot files/directories (except `serve-dot-names`
   entries), symlinks and special files are skipped,
5. reads the DNS resolver configuration, the CA root certificates and the
   MIME type table once. Go normally loads these files from `/etc` only at
   the moment they are first needed ("lazily") and then keeps them cached
   in memory for the rest of the process's life. Inside the jail `/etc` no
   longer exists, so the server forces that first read now — the cached
   copies are what keep ACME renewals (DNS lookups, TLS verification) and
   content-type detection working later,
6. enters the jail: `chroot`, drop to the first of `www`, `www-data`,
   `_www`, `nobody` that exists, verify root cannot be regained, clear the
   environment (Linux, macOS and the BSDs; on Windows only the working
   directory is changed and the environment cleared),
7. serves, obtaining and renewing certificates through the parent.

### File system access — what, why, and the two modes

- **The `chmod` and `chown` in step 3 are real and permanent.** The chmod
  exists because after the privilege drop the child runs as an unprivileged
  user that could not read root-owned content otherwise — and because
  nothing, including the serving process itself, should be able to *write*
  web content. The chown to root exists because permissions alone do not
  bind an owner: a file owned by the jail user could simply be chmodded
  writable again by a compromised serving process. Root-owned read-only
  files are immutable for the jailed child, which runs without any
  capabilities. Symbolic links are left untouched.
- **`serve-files-not-in-cache: true` (default):** the child chroots *into
  the web root* and keeps read-only access to it. Requests for files that
  are not cached — larger than `max-cacheable-file-size`, or created after
  startup — are answered from disk, opened read-only per request. This is
  the mode for serving big files (videos, archives) without holding them in
  RAM.
- **`serve-files-not-in-cache: false`:** the child chroots into a freshly
  created empty directory under the system temp directory and loses every
  last bit of disk access. Files above the cache limit are reported at
  startup and answered with 404.
- **Content updates:** cached files are never re-read — deploy new content,
  then restart. In the default mode, changes to *uncached* files are visible
  immediately, since those are read per request.
- The certificate cache and the log file belong to the parent and must be
  outside the web root (this is enforced at startup). The certificate cache
  is created with mode `0700` and contains the Let's Encrypt account key and
  all private keys — protect and back it up accordingly.

## Build and run

    CGO_ENABLED=0 go build -o sslserver .

The binary is fully static (no cgo). Run it as root so it can bind the
privileged ports, `chmod` foreign-owned content, and enter the jail:

    sudo ./sslserver

On the first start a fully commented `config.yml` is created **next to the
executable**; every entry states what it does and its default value, so any
change can be reverted later. A different config file can be given with:

    ./sslserver -config /etc/sslserver/config.yml

Relative paths inside the config are resolved against the config file's
directory, so the working directory never matters. Without root (and on
Windows) the server runs without the jail and prints a warning — useful for
development with unprivileged ports. The `-child` flag is used internally
by the parent to start the server child; don't pass it yourself.

## Installing on a Linux server

Build the static binary (cross-compiling works from any machine, e.g.
`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o sslserver .`) and give
it a directory of its own — the config, web root, certificate cache and log
are all created next to the binary, so that one directory holds everything:

    sudo mkdir -p /opt/sslserver
    sudo cp sslserver /opt/sslserver/
    sudo /opt/sslserver/sslserver    # creates config.yml and www_static/; stop with Ctrl-C

Put your content into `/opt/sslserver/www_static/<your-domain>/`, set
`acme-email` in the config, and make sure the domain's DNS points at this
server and ports 80/443 are reachable. To start it on boot, create
`/etc/systemd/system/sslserver.service`:

    [Unit]
    Description=sslserver static web server
    After=network-online.target
    Wants=network-online.target

    [Service]
    ExecStart=/opt/sslserver/sslserver
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target

Then run `sudo systemctl enable --now sslserver`. The `Restart=on-failure`
also covers a crashed server child, because the parent exits with it. Logs
end up in `/opt/sslserver/server.log` and in `journalctl -u sslserver`.

## Configuration

Both processes read the file. Unknown or misspelled keys are rejected at
startup. Durations use Go syntax (`15s`, `48h`).

| Key | Default | Meaning |
| --- | --- | --- |
| `web-root-directory` | `www_static` | One subdirectory per domain, **named exactly like the domain it serves** (e.g. `www_static/example.com`, in lowercase ASCII/punycode form); created if missing. All contents are permanently made world-readable and read-only at startup. |
| `chown-web-root` | `true` | Also transfer ownership of all web root contents to root at startup (when started as root). Without this, content owned by the jail user could be chmodded writable again by the serving process. Disable if a non-root user deploys the content. |
| `certificate-cache-directory` | `certcache` | Let's Encrypt account key, private keys and certificates. Parent only; must be outside the web root. |
| `acme-email` | `""` | Contact for the Let's Encrypt account (expiry notices). Optional but recommended. |
| `http-addr`, `https-addr` | `:http`, `:https` | Listen addresses; service names are allowed. The HTTP→HTTPS redirect always targets the default port 443. |
| `self-signed-domains` | `[localhost, 127.0.0.1]` | Domains/IPs that never use Let's Encrypt. A web root directory of the same name is only needed if content should be served for them. |
| `www-alias` | `false` | Serve `www.example.com` from the `example.com` directory and vice versa when the aliased name has no own directory. Aliases use the original's certificate type; their certificates are obtained on first use. |
| `serve-dot-names` | `[.well-known]` | Dot files/directories with these exact names are cached and served despite starting with a dot. |
| `server-name` | `dma-srv` | `Server` response header (`""` = no header). |
| `http-headers` | security defaults | Response headers, merged over the defaults (HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`). Set a value to `""` to drop a default; add any extra header (e.g. `Cache-Control`) as a new key. |
| `domains` | `{}` | Per-domain overrides, keyed by domain name (aliases inherit them): `http-headers` merged over the global ones, and `serve-http: true` to serve the site over plain HTTP instead of redirecting (HTTPS keeps working; HSTS is never sent over plain HTTP). |
| `certificate-expiry-refresh-threshold` | `48h` | Renew certificates this long before they expire (minimum `1h`). Also determines self-signed validity (threshold + 14 days). |
| `max-request-timeout`, `max-response-timeout`, `max-idle-timeout` | `15s`, `60s`, `60s` | Read, write and keep-alive timeouts of both servers. |
| `max-connections` | `1024` | Maximum concurrent connections per listener (`0` = unlimited). |
| `serve-files-not-in-cache` | `true` | `true`: jail into the web root and serve uncached files from disk. `false`: jail into an empty directory, cache-only (see above). |
| `max-cacheable-file-size` | `1048576` | Files up to this size (in bytes) are cached in memory at startup. Larger files are served from disk, or not at all — depending on `serve-files-not-in-cache`. |
| `max-total-cache-size` | `268435456` (256 MiB) | Stop caching when the total of cached bytes reaches this limit; further files are treated like files above `max-cacheable-file-size` (`0` = unlimited). |
| `log-requests` | `true` | Log client address, method, host and path of every request. |
| `log-file` | `server.log` | Written by the parent; must be outside the web root (`""` = stdout only). |
| `log-max-age` | `720h` (30 days) | Delete rotated-out log files older than this, checked hourly (`0` = keep them until the rotation count replaces them). |

## Request handling

- The `Host` header — port stripped, internationalized names converted to
  their ASCII (punycode) form — must match a domain directory or a
  self-signed domain; otherwise 404. `example.com` and `www.example.com`
  are two separate directories unless `www-alias` is enabled, which serves
  either name from the other's directory when it has no own one. A
  top-level symlink (`www.example.com -> example.com`) is served as an
  explicit alias of its target the same way; symbolic links *inside* a
  site's content are ignored. Domain directories must be named in their
  lowercase ASCII form (the server warns at startup if not).
- Only `GET` and `HEAD` are answered; other methods get `405`.
- URL paths are normalized first; any path segment starting with a dot is
  rejected — hidden files are neither cached nor served — unless its name
  is listed in `serve-dot-names` (by default `.well-known`, for standard
  URLs like `/.well-known/security.txt`). `/` and `…/dir/` serve the
  directory's `index.html`; `/dir` redirects (`301`) to `/dir/` when that
  directory has an index.
- Cached files of known compressible types are also held as a gzip variant
  (created once at startup when it saves at least 10%) and served with
  `Content-Encoding: gzip` to clients that accept it, with a correct `Vary`
  header. Files served from disk are not compressed.
- Conditional requests are answered with `304`: every cached file carries a
  strong `ETag` (a content hash, computed once at startup) plus
  `Last-Modified`. `Range` requests are supported; `Content-Type` comes
  from the file extension.
- Everything else — unknown domain, traversal attempts, missing files —
  gets a plain `404` without details.

## Certificates

- **Let's Encrypt** for every web root domain not listed in
  `self-signed-domains`: obtained on first use, prefetched right after
  startup, renewed automatically before expiry. The jailed child performs
  the ACME exchange and the parent persists the results, so renewals need
  no restart and survive one. Alias names (`www-alias` or domain symlinks)
  whose certificate is already in the cache are loaded and renewed at
  startup like normal domains; an alias without a cached certificate gets
  one on its first request, which proves its DNS actually points at this
  server.
- **Self-signed** (ECDSA P-256, with subject alternative names, IP
  addresses supported) for the `self-signed-domains`, and as automatic
  fallback whenever Let's Encrypt fails — Let's Encrypt is retried on
  later handshakes. Self-signed certificates live only in memory.
- The on-disk layout is the standard `autocert` cache; an existing cache
  directory from an earlier installation keeps working.

## Logging

Log lines are prefixed `P` (parent) or `C` (child, the actual server).
The parent writes everything to stdout and — unless `log-file` is empty —
to the log file, rotating at 5 MB into `server.log.1` … `.3` and deleting
rotated files older than `log-max-age`.

## Development

    go vet .
    go test .

Use the package path `.` rather than `./...` — the web root may contain
directories the Go tool cannot read.
