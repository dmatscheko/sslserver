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

### Timer and shutdown

- Loads all SSL certificates at startup and retrieves their expiration time.
- If configured to do so, the web server terminates a configured duration before the first SSL certificate expires.
- In this case, you have to restart the server with a script, it then creates a new Let's Encrypt certificate.

## Build and run

    go run .

or (on Linux)

    go build .
    sudo ./start.sh

or (on Windows)

    go build .
    sslserver

## Configuration

At startup a `config.yml` is automatically created. Those are the values that can be changed:

### Basic settings
* `web-root-directory`: This specifies the the base directory (web root) to serve static files from. Warning, the permissions for all files will be set to `a=r`, and for all directories to `a=rx`. The default value is `jail/www_static`.
* `http-addr`: This specifies the HTTP address to bind the server to. The default value is `:http`.
* `https-addr`: This specifies the HTTPS address to bind the server to. The default value is `:https`.
### Certificate handling
* `lets-encrypt-domains`: This is a white list of domains that are allowed to fetch a Let's Encrypt certificate. The default value is `- example.com`.
* `self-signed-domains`: This is a white list of domains for which self-signed certificates are allowed. The domains for Let's Encrypt are automatically added to this list, but you can include additional domains that are only allowed for self-signed certificates. The default value is `- localhost`, `- 127.0.0.1`.
* `certificate-cache-directory`: Let's Encrypt certificates are stored in this directory. The server has to be able to write certificates into this directory. It should therefore not be inside the jail. The default value is `certcache`.
* `terminate-on-certificate-expiry`: This determines whether the program should exit when a certificate is about to expire. If set to true, this allows caching the certificates to the hard disk after the next start. Note that an external script will have to restart the server. Also note, that the server will only be restarted on Linux, because it doesn't make sense to do so on Windows. The reason is, that the jail doesn't work on Windows. The default value is `false`.
* `certificate-expiry-refresh-threshold`: This specifies, how long before their expiration the certificates should be renewed. The default value is `48h0m0s` (48 hours).
### HTTP timeouts
* `max-request-timeout`: This specifies the maximum duration to wait for a request to complete. The default value is `15s` (15 seconds).
* `max-response-timeout`: This specifies the maximum duration to wait for a response to complete. The default value is `60s` (60 seconds).
### Jail dependent settings
* `serve-files-not-in-cache`: This can only be `true`, if `jail-process` is set to `false`, or if the `web-root-directory` is inside the `jail-directory`. It determines whether to serve files that are not cached in memory. The default value is `false`.
* `max-cacheable-file-size`: This specifies the maximum size for files that are cached in memory. Files can only be served, if they are cached (file size <= `max-cacheable-file-size`), or the `web-root-directory` is inside the `jail-directory`, or the server is NOT jailed. The default value is `1048576` (1 MB).
* `jail-process`: This determines whether the process should be jailed. If a process is jailed, no file can be larger than the size specified in `max-cacheable-file-size`, or the `web-root-directory` must be inside the `jail-directory`. Jailing the process only works on Linux. On Windows, only the working directory is changed to the `jail-directory` to maintain similar directory access behavior to Linux in the settings. The default value is `true`.
* `jail-directory`: The directory in which to jail the process. Warning, the permissions for all files will be set to `a=r`, and for all directories to `a=rx`. The default value is `jail`.
### Logging
* `log-requests`: Log the client IP and the URL path of each request. Warning, if `jail-process` is set to `true`, the logfiles can not be rotated and will grow indefinitely. The default value is `true`.
* `log-file`: The name of the log file. If the name is empty (= `""`), the log output will only be written to `stdout`. The default value is `server.log`.

## TODO

* Create configured directories if they don't exist.
* Set the correct caching headers.
* Implement security relevant HTTP headers.
* Test the behavior of Let's Encrypt when it is unable to store its certificates to the file system. Maybe it crashes.
* Maybe find a way to write log files. Open the log file before activating jail?
* Consider also storing the self-signed certificates.
* Implement a way to restart the application from within the application itself.
