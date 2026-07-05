package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/netutil"
)

// runChild binds the ports, fills the file cache, drops into the jail and
// serves until it receives SIGINT/SIGTERM (forwarded by the parent).
func runChild() {
	certs := newCertManager()

	// Bind both ports first: this is what needs root, the jail comes after.
	httpLn, err := net.Listen("tcp", config.HttpAddr)
	if err != nil {
		log.Fatal(err)
	}
	httpsLn, err := net.Listen("tcp", config.HttpsAddr)
	if err != nil {
		log.Fatal(err)
	}
	if config.MaxConnections > 0 {
		httpLn = netutil.LimitListener(httpLn, config.MaxConnections)
		httpsLn = netutil.LimitListener(httpsLn, config.MaxConnections)
	}
	log.Printf("Listening on %s (HTTP) and %s (HTTPS)", config.HttpAddr, config.HttpsAddr)

	hardenWebRoot(config.WebRootDirectory)
	if err := fillCache(); err != nil {
		log.Fatal(err)
	}

	// Go reads the DNS resolver config, the CA roots and the MIME table
	// from /etc only when they are first used, and then keeps them cached
	// in memory. Force that first use now: inside the jail /etc no longer
	// exists, and ACME renewals (DNS lookups, TLS verification) and
	// content-type detection depend on this data.
	net.LookupHost("acme-v02.api.letsencrypt.org")
	x509.SystemCertPool()
	mime.TypeByExtension(".css")

	// serve-files-not-in-cache=true keeps read-only access to the web root
	// (the jail root IS the web root). false jails into an empty directory,
	// which removes every last bit of disk access.
	jailDir := config.WebRootDirectory
	if !config.ServeFilesNotInCache {
		if jailDir, err = os.MkdirTemp("", "sslserver-empty-jail-"); err != nil {
			log.Fatal(err)
		}
		os.Chmod(jailDir, 0555)
	}
	switch chrooted := enterJail(jailDir); {
	case !config.ServeFilesNotInCache:
		diskRoot = "" // never read from disk again
	case chrooted:
		diskRoot = "/" // the web root is the file system root now
	default:
		if diskRoot, err = filepath.Abs(config.WebRootDirectory); err != nil {
			log.Fatal(err)
		}
	}

	httpSrv := &http.Server{
		ReadTimeout:  config.MaxRequestTimeout,
		WriteTimeout: config.MaxResponseTimeout,
		IdleTimeout:  config.MaxIdleTimeout,
		// Serves ACME http-01 challenges; everything else is redirected to
		// HTTPS or, for serve-http domains, served directly.
		Handler: certs.acme.HTTPHandler(http.HandlerFunc(serveHTTPFallback)),
	}
	httpsSrv := &http.Server{
		ReadTimeout:  config.MaxRequestTimeout,
		WriteTimeout: config.MaxResponseTimeout,
		IdleTimeout:  config.MaxIdleTimeout,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// TLS 1.2 suites per https://ssl-config.mozilla.org intermediate;
			// TLS 1.3 suites are not configurable and always secure.
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			GetCertificate: certs.GetCertificate,
			NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
		},
		Handler: http.HandlerFunc(serveFiles),
	}

	errc := make(chan error, 2)
	go func() { errc <- httpSrv.Serve(httpLn) }()
	go func() { errc <- httpsSrv.ServeTLS(httpsLn, "", "") }()
	go certs.prewarm()
	log.Println("Serving files ...")

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sigc:
		log.Println("Shutting down on signal:", s)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpSrv.Shutdown(ctx)
		httpsSrv.Shutdown(ctx)
	case err := <-errc:
		log.Fatal(err) // one of the servers failed
	}
}
