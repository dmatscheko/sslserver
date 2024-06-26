# A web server that serves static files over HTTPS

A web server that serves static files over HTTPS, manages TLS certificates, has security measures for Linux, and can stop when a certificate expires.

## Description
### General features

- Serves static files from the subdirectory `./jail/www_static`.
- Reads each file only once and caches it in memory.
- Serves the static files via HTTPS.
- Redirects all HTTP requests to HTTPS.

### TLS certificate management

- Automatically fetches TLS certificates from Let's Encrypt.
- Creates a self signed certificate if Let's Encrypt is unreachable or denies a certificate for a white listed domain.
- You need to configure the white listed domains.

### Security measures

- If compiled and executed on Linux, the server drops all privileges and jails itself in the `./jail` subdirectory.

## Build and run

    go run

or (on Linux)

    go build
    sudo ./start.sh

or (on Windows)

    go build
    sslserver

## Configuration

At startup a `config.yml` is automatically created. Those are the values that can be changed:

### Basic settings
* `web-root-directory`: This specifies the the base directory (web root) to serve static files from. Warning, the permissions for all files will be set to `a=r`, and for all directories to `a=rx`. The default value is `jail/www_static`.
* `http-addr`: This specifies the HTTP address to bind the server to. The default value is `:http`.
* `https-addr`: This specifies the HTTPS address to bind the server to. The default value is `:https`.
### Certificate handling
* `lets-encrypt-domains`: This is a white list of domains that are allowed to fetch a Let's Encrypt certificate. The default value is empty.
* `self-signed-domains`: This is a white list of domains for which self-signed certificates are allowed. The domains for Let's Encrypt are automatically added to this list, but you can include additional domains that are only allowed for self-signed certificates. The default value is `localhost`, `127.0.0.1`.
* `certificate-cache-directory`: Let's Encrypt certificates are stored in this directory. The server has to be able to write certificates into this directory. It should therefore not be inside the jail or it will be set to read only. The default value is `certcache`.
* `certificate-expiry-refresh-threshold`: This specifies, how long before their expiration the certificates should be renewed. The default value is `48h0m0s` (48 hours).
### HTTP timeouts
* `max-request-timeout`: This specifies the maximum duration to wait for a request to complete. The default value is `15s` (15 seconds).
* `max-response-timeout`: This specifies the maximum duration to wait for a response to complete. The default value is `60s` (60 seconds).
* `max-idle-timeout`: This specifies the maximum duration to wait for a follow up request. The default value is `60s` (60 seconds).
### Jail dependent settings
* `serve-files-not-in-cache`: This can only be `true`, if `jail-process` is set to `false`, or if the `web-root-directory` is inside the `jail-directory`. It determines whether to serve files that are not cached in memory. If this is `false`, the server will not even try to read newer files into the cache or serve big files directly from the disk. The default value is `false`.
* `max-cacheable-file-size`: This specifies the maximum size for files that are cached in memory. Files can only be served, if they are cached (file size <= `max-cacheable-file-size`), or the `web-root-directory` is inside the `jail-directory`, or the server is NOT jailed. The default value is `1048576` (1 MB).
* `jail-process`: This determines whether the process should be jailed. If a process is jailed, no file can be larger than the size specified in `max-cacheable-file-size`, or the `web-root-directory` must be inside the `jail-directory`. Jailing the process only works on Linux. On Windows, only the working directory is changed to the `jail-directory` to maintain similar directory access behavior to Linux in the settings. The default value is `true`.
* `jail-directory`: The directory in which to jail the process. Warning, the permissions for all files will be set to `a=r`, and for all directories to `a=rx`. The default value is `jail`.
### Logging
* `log-requests`: Log the client IP and the URL path of each request. Warning, if `jail-process` is set to `true`, the logfiles can not be rotated and will grow indefinitely. The default value is `true`.
* `log-file`: The name of the log file. If the name is empty (= `""`), the log output will only be written to `stdout`. The default value is `server.log`.

## TODO

* Test the behavior of Let's Encrypt when it is unable to store its certificates to the file system. Maybe it crashes.
* Consider also storing the self-signed certificates.
* Implement a way to restart the application from within the application itself.
