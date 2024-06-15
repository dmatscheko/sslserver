package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var httpServer *http.Server
var httpsServer *http.Server

// Custom HTTP handler to log requests
func loggingHTTPHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("HTTP Request: %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func runServer(manager *autocert.Manager) {
	// Create a wait group with a count of 2.
	// This indicates that we are waiting for two signals.
	// The two signals will be sent when the two servers have finished binding to their addresses.
	var wgBindDone sync.WaitGroup
	wgBindDone.Add(2)

	// Create a wait group with a count of 2.
	// This indicates that we are waiting for two signals.
	// The two signals will be sent when the two servers have been terminated.
	var wgServerClosed sync.WaitGroup
	wgServerClosed.Add(2)

	// Create a wait group with a count of 1.
	// This indicates that we are waiting for one signal.
	// The signal will be sent after the servers is jailed.
	var wgJailed sync.WaitGroup
	wgJailed.Add(1)

	//
	// ========
	// HTTP SERVER
	// ========
	//

	// Create an HTTP server that redirects all requests to HTTPS.
	httpServer = &http.Server{
		Addr:         config.HttpAddr,
		ReadTimeout:  config.MaxRequestTimeout,
		WriteTimeout: config.MaxResponseTimeout,
		IdleTimeout:  config.MaxIdleTimeout,
		Handler:      loggingHTTPHandler(manager.HTTPHandler(nil)), // from autocert manager
		// Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 	// Redirect the request to HTTPS.
		// 	http.Redirect(w, r, "https://"+r.Host+r.URL.Path, http.StatusFound) // TODO: get config.HttpsAddr and redirect to this port. Or better, create a config variable for this, because there can be a proxy in front.
		// }),
	}

	// Start the HTTP server in a separate goroutine.
	go func() {
		log.Println("Starting HTTP server on", httpServer.Addr)

		// Listen on the specified address.
		ln, err := net.Listen("tcp", httpServer.Addr)
		if err != nil {
			log.Fatal(err)
		}

		// Close the listener when the function returns.
		defer ln.Close()

		// Send a signal on the wait group when the listener is ready.
		wgBindDone.Done()

		// Wait for the wait group to reach zero.
		// This will happen when the server has been jailed.
		wgJailed.Wait()

		// Serve HTTP connections on the listener.
		err = httpServer.Serve(ln)
		if err != nil {
			log.Fatal(err)
		}

		// Send a signal on the wait group when the server has closed.
		wgServerClosed.Done()
	}()

	//
	// ========
	// HTTPS SERVER
	// ========
	//

	// Create an HTTPS server that serves files from the "static" directory.
	httpsServer = &http.Server{
		Addr:         config.HttpsAddr,
		ReadTimeout:  config.MaxRequestTimeout,
		WriteTimeout: config.MaxResponseTimeout,
		IdleTimeout:  config.MaxIdleTimeout,
		TLSConfig: &tls.Config{
			// Set the GetCertificate callback for the TLS config to a function
			// that tries to fetch a certificate.
			GetCertificate: MyGetCertificate,
			NextProtos: []string{
				"h2", "http/1.1", // enable HTTP/2
				acme.ALPNProto, // enable tls-alpn ACME challenges
			},
		},
		Handler: http.HandlerFunc(serveFiles), // Serve files from the "static" directory.
	}

	// Start the HTTPS server in a separate goroutine.
	go func() {
		log.Println("Starting HTTPS server on", httpsServer.Addr)

		// Listen on the specified address.
		ln, err := net.Listen("tcp", httpsServer.Addr)
		if err != nil {
			log.Fatal(err)
		}

		// Close the listener when the function returns.
		defer ln.Close()

		// Send a signal on the wait group when the listener is ready.
		wgBindDone.Done()

		// Wait for the wait group to reach zero.
		// This will happen when the server has been jailed.
		wgJailed.Wait()

		// Serve TLS connections on the listener.
		err = httpsServer.ServeTLS(ln, "", "")
		if err != nil {
			log.Fatal(err)
		}

		// Send a signal on the wait group when the server has closed.
		wgServerClosed.Done()
	}()

	// Wait for the wait group to reach zero.
	// This will happen when both the HTTP and the HTTPS server terminate.
	wgBindDone.Wait()

	//
	// ========
	// BOTH SERVER DID BIND TO THEIR PORT
	// ========
	//

	// Initialize (fill) the white list and the cert cache.
	log.Println("Checking certificates...")
	initCertificates(manager)

	// Jail process as good as possible

	// Convert the relative path to an absolute path.
	absoluteBaseDirectory, err := filepath.Abs(config.WebRootDirectory)
	if err != nil {
		log.Fatalln("Could not get absolute path for web root:", err)
	}

	// Remove write permissions, drop privileges and jail process if running on Linux. Only remove write permissions on windows.
	Jail(absoluteBaseDirectory)

	// Send a signal on the wait group when the server has been jailed.
	wgJailed.Done()

	// Close both server.	// TODO: do this on signal terminate.
	// terminateServer(httpServer, httpsServer)

	log.Println("Serving files ...")

	// Wait for the wait group to reach zero.
	// This will happen when both the HTTP and the HTTPS server terminate.
	wgServerClosed.Wait()

	//
	// ========
	// BOTH SERVER HAVE CLOSED
	// ========
	//

	log.Println("Server terminated.")
}

// terminateServer shuts down the given servers with a timeout of 10 seconds.
//
// This function calls the http.Server.Shutdown() method for each server and passes in
// a context with a timeout. If the server has not completed shutdown by the end of the
// timeout, the context is cancelled and the server is terminated immediately.
func terminateServerList(servers ...*http.Server) {
	// Create a context with a timeout of 10 seconds.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel() // Cancel the context when the function returns.

	// Create a wait group with a count of the number of servers.
	var wgShutdown sync.WaitGroup
	wgShutdown.Add(len(servers))

	// Shut down the servers in parallel go routines.
	for _, server := range servers {
		go func(server *http.Server) {
			// Shut down the server using the context.
			// This will cause the server to stop accepting new connections.
			// and wait for all existing connections to be closed.
			err := server.Shutdown(ctx)
			if err != nil {
				log.Fatal("Server shutdown:", err)
			}

			// Send a signal on the wait group when the server has shut down.
			wgShutdown.Done()
		}(server)
	}

	// Wait for the wait group to reach zero.
	// This will happen when all servers have shut down or the timeout has been reached.
	wgShutdown.Wait()
}

func terminateServer() {
	terminateServerList(httpServer, httpsServer)
}
