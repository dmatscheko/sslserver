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

* `domains-lets-encrypt`: This is a white list of domains that are allowed to fetch a Let's Encrypt certificate. The default value is `- example.com`.
* `domains-self-signed`: This is a white list of domains for which self-signed certificates are allowed. The domains for Let's Encrypt are automatically added to this list, but you can include additional domains that are only allowed for self-signed certificates. The default value is `- localhost`, `- 127.0.0.1`.
* `terminate-if-certificate-expires`: This determines whether the program should exit when a certificate is about to expire. If set to true, this allows caching the certificates to the hard disk after the next start. Note that an external script will have to restart the server, and the server will only be restarted on Linux, because it doesn't make sense to do so on Windows. The default value is `false`.
* `duration-to-certificate-expiry-refresh`: This specifies how long before a certificate expires that self-signed certificates should be renewed. The default value is `48h0m0s` (48 hours).
* `serve-non-cached-files`: This determines whether to serve files if they are not cached in memory. The default value is `false`.
* `cache-file-size-limit`: This specifies the maximum size for files that are cached in memory. If files are not cached, and the server is jailed, it might be impossible to access the files. The default value is `10485760` (10 MB).

## TODO

* Set the correct caching headers.
* Implement security relevant HTTP headers.
* Test the behavior of Let's Encrypt when it is unable to store its certificates to the file system. Maybe it crashes.
* Consider also storing the self-signed certificates.
* Implement a way to restart the application from within the application itself.
