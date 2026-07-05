# sslserver — Features & Improvement Opportunities

> **Note:** This analysis describes the code as of commit `ed580ee`. The
> server was subsequently rewritten from scratch, addressing these findings;
> file and line references below refer to the old implementation.

A small static HTTPS file server in Go (~1500 LoC, 9 files) with automatic Let's Encrypt
certificates and a privilege-separation design: a **parent process** keeps disk access for
the certificate cache, while a **child process** runs the actual servers and is meant to be
chroot-jailed. The two communicate over stdin/stdout with a simple line-based protocol
(`[get]`/`[put]`/`[delete]`/`[terminate]`).

## Features

### Serving
- Static file serving over HTTPS with virtual hosting: each subdirectory of the web root
  (`www_static/<domain>/`) is served for the matching `Host` header (`files.go`).
- In-memory file cache filled at startup; entries are refreshed when the file's mtime
  changes. Files above `max-cacheable-file-size` are streamed from disk instead (`files.go`).
- `http.ServeContent` is used, so Range requests, `If-Modified-Since` and correct
  Content-Type detection come for free.
- HTTP (port 80) side handles ACME http-01 challenges and redirects everything else to
  HTTPS via `autocert.Manager.HTTPHandler` (`server.go`).
- HTTP/2 enabled via ALPN.

### TLS / certificates
- Automatic Let's Encrypt certificates through `x/crypto/acme/autocert`, including the
  TLS-ALPN-01 challenge; the LE domain whitelist is derived from the web-root
  subdirectory names (`config.go`, `main.go`).
- Fallback to an on-the-fly self-signed certificate (RSA-4096) when LE fails or for
  domains on the `self-signed-domains` whitelist (`certificates.go`).
- Custom `GetCertificate` with in-memory cert cache, expiry check
  (`certificate-expiry-refresh-threshold`) and re-fetch on expiry; all domains are
  pre-warmed at startup (`initCertificates`).
- Certificates are persisted by the *parent* process (`autocert.DirCache`); the child
  reaches the cache only through the IPC protocol, so the jailed child needs no disk write
  access (`main.go`, `certificates.go`).
- IDNA/punycode normalization of SNI names and Host headers.

### Security
- Linux jail (`linux_jail.go`): chroot into the web root, `setuid`/`setgid` to `www`/
  `nobody` (cgo `getpwnam` wrapper in `linux_pwd.go`), drop **all** capabilities via
  libcap, clear the environment. Windows fallback: chdir + read-only permissions only.
- Web root is chmod-ed read-only (files `0444`, dirs `0555`) at startup.
- Strict request validation: Host must be on the domain whitelist; URL paths must match a
  conservative regex (rejects dotfiles, traversal, unexpected characters) (`files.go`).
- Hardened TLS: min TLS 1.2, Mozilla-intermediate cipher suites.
- Security response headers: `Strict-Transport-Security`, `Content-Security-Policy`,
  `X-Content-Type-Options`, `X-Frame-Options` (all configurable) plus `Referrer-Policy`,
  `Permissions-Policy`, `X-XSS-Protection`; `Server` header is configurable.

### Configuration & operations
- YAML config (`config.yml`) auto-generated with defaults on first start; sanity checks
  and fallbacks for every value; config printed at startup (`config.go`).
- Optional request logging; logs go to stdout and optionally a log file, with `P `/`C `
  prefixes distinguishing parent and child (`logrotate.go`).
- Graceful shutdown helper with 10 s timeout (`terminateServer`, triggered by the
  `[terminate]` IPC command).
- Servers bind their ports first (needs root), and only then is the jail entered —
  coordinated with WaitGroups (`server.go`).

## Improvement opportunities

### Bugs / correctness
1. **Data races on shared maps.** `fileCache` (`files.go`), `certCache` and
   `certCacheBytes` (`certificates.go`) are plain maps written from concurrent request/
   handshake goroutines — Go will panic with `concurrent map writes` under load. Needs
   `sync.RWMutex` or `sync.Map`.
2. **Self-signed domains are not excluded from the LE whitelist.** In
   `getAllowedDomainsFromSubdirectories` (`config.go`) the `continue` only affects the
   inner loop; the `append` always runs, so directories like `localhost` would still get
   Let's Encrypt attempts. Needs a labeled continue or a `skip` flag.
3. **Disk reads use paths relative to CWD, not the web root.** `serveFiles` builds
   `domain + urlPath` without prepending `config.WebRootDirectory`; this only works after
   the (currently disabled) jail has chdir-ed into the web root. As deployed
   (`run-main.sh` doesn't `cd` into it), `os.Open` fails for every request: cache refresh
   never happens and files larger than `max-cacheable-file-size` are unservable (404).
4. **IPC responses aren't correlated.** `DirCache.Get` sends a request and then waits on
   the shared `parentToChildCh`; two concurrent `Get`s (e.g. two renewals) can receive
   each other's response — there is no request ID, and a mismatched name is simply
   dropped as a cache miss (`certificates.go`).
5. **Startup race window.** The HTTPS listener starts serving before `initCertificates`
   runs, so an early handshake hits `m == nil` (panic) or assigns into the nil
   `certCacheBytes` map (`server.go`, `certificates.go`).
6. **In-band signaling on stdout.** The child's logger and the IPC writer share stdout; a
   log line emitted between the length line and the data payload corrupts the protocol,
   and any log line that equals a command keyword desyncs it (`main.go`,
   `logrotate.go`). Consider a dedicated pipe/fd for the protocol, or framing.
7. **Self-signed certs have no SAN and a fixed serial.** Modern clients reject
   certificates without Subject Alternative Names even when manually trusted; the serial
   is hardcoded to `412294` (`certificates.go`). Add `DNSNames`, randomize the serial,
   and consider ECDSA instead of RSA-4096 (keygen currently blocks a handshake for
   seconds).
8. **`log.Fatal` used for routine events.** Child exit makes the parent's reader
   goroutine `log.Fatal` on EOF instead of shutting down cleanly; a failed `Shutdown`
   also `log.Fatal`s (`main.go`, `server.go`).

### Missing features
9. **The jail is disabled** — the `Jail(...)` call is commented out (`server.go`), which
   is the reason for bugs 3's "works by accident" state and the TODO in `main.go`
   ("push new certificates through the client-server communication and enable the jail
   again"). Re-enabling it is the project's own top priority.
10. **No signal handling.** SIGINT/SIGTERM don't trigger `terminateServer`; nothing ever
    sends `[terminate]`. The parent also never restarts a child that exited (a README
    TODO).
11. **Log rotation is dead code** — fully commented out in `logrotate.go`; `server.log`
    grows without bound. The plan to move logging into the parent would also fix bug 6.
12. **No directory index handling** beyond `/` → `/index.html`: `/subdir/` 404s instead
    of serving `/subdir/index.html`. The path regex also rejects legitimate names
    (dots in directory names, spaces, unicode) (`files.go`).
13. **Host headers with ports fail validation.** `r.Host` can be `example.com:8443` on
    non-standard ports; the port should be stripped before the whitelist check
    (`files.go`).
14. **No cache/conditional headers beyond Last-Modified** — no `Cache-Control`, no ETag —
    and no gzip/brotli compression; both are cheap wins for a static server (the file
    cache could store pre-compressed variants).
15. **ACME account email is hardcoded** (`admin-le@14.gy` in `main.go`) — should be a
    config option. The HTTP→HTTPS redirect target port is likewise not configurable
    (relevant behind a proxy; noted in a TODO).

### Code quality / maintenance
16. **No tests** — no `*_test.go` at all. The pure helpers (`validateAndCleanPath`,
    `validateDomain`, `getAllowedDomainsFromSubdirectories`, the IPC framing) are easy,
    high-value test targets.
17. **Deprecated APIs**: `ioutil.ReadFile/WriteFile` (→ `os.*` since Go 1.16),
    `tls.Config.PreferServerCipherSuites` (ignored since Go 1.18), `X-XSS-Protection`
    header (obsolete guidance). `go.mod` pins Go 1.18 and carries unused indirect
    dependencies (certmagic, zerossl, zap…) — `go mod tidy` after cleanup.
18. **`readConfig` works by accident** when `config.yml` is missing: the freshly
    marshaled data is assigned to a *shadowed* `data`, so the later `Unmarshal` parses
    the outer nil slice (harmless only because defaults remain). Log messages also say
    `config.yaml` while the file is `config.yml` (`config.go`).
19. **README is out of sync with the code**: it documents removed options
    (`jail-process`, `jail-directory`, `lets-encrypt-domains`), wrong defaults
    (`jail/www_static`, `serve-files-not-in-cache: false`) and a `start.sh` that doesn't
    exist (`run-main.sh` does).
20. **Idle-timeout log spam**: the IPC writer loops log "Timeout waiting for command"
    every 10 s when there is simply no traffic (`main.go`) — the `time.After` cases can
    be dropped.
21. **Duplicated punycode/validation logic** in `MyGetCertificate` and
    `GetSelfSignedCertificate`. Also a copy-paste bug in `linux_pwd.go:51`:
    `newPasswdFromC` fills the `GID` field from `pw_uid`, so the jail would
    `setregid` to the user's UID instead of its GID (masked today because
    `www`/`nobody` usually have identical uid/gid — and the jail is disabled).
