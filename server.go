package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

func main() {
	// Read config file.
	readConfig()

	// Initialize (fill) the white list and the cert cache.
	shortestDuration := initCertificates()

	// Initialize (fill) the file cache.
	fillCache("static")

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

	//
	// ========
	// HTTP SERVER
	// ========
	//

	// Create an HTTP server that redirects all requests to HTTPS.
	httpServer := &http.Server{
		Addr:         ":80",
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Redirect the request to HTTPS.
			http.Redirect(w, r, "https://"+r.Host+r.URL.Path, http.StatusFound)
		}),
	}

	// Start the HTTP server in a separate goroutine.
	go func() {
		log.Println("Starting HTTP server on port 80.")

		// Get the address of the server.
		addr := httpServer.Addr
		// If the address is not set, use the default ":http".
		if addr == "" {
			addr = ":http"
		}

		// Listen on the specified address.
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatal(err)
		}

		// Close the listener when the function returns.
		defer ln.Close()

		// Send a signal on the wait group when the listener is ready.
		wgBindDone.Done()

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
	httpsServer := &http.Server{
		Addr:         ":443",
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		TLSConfig: &tls.Config{
			// Set the GetCertificate callback for the TLS config to a function
			// that tries to fetch a certificate.
			GetCertificate: getCertificate,
		},
		Handler: http.HandlerFunc(serveFiles), // Serve files from the "static" directory.
	}

	// Start the HTTPS server in a separate goroutine.
	go func() {
		log.Println("Starting HTTPS server on port 443.")

		// Get the address of the server.
		addr := httpsServer.Addr
		// If the address is not set, use the default ":https".
		if addr == "" {
			addr = ":https"
		}

		// Listen on the specified address.
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatal(err)
		}

		// Close the listener when the function returns.
		defer ln.Close()

		// Send a signal on the wait group when the listener is ready.
		wgBindDone.Done()

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

	// Drop privileges and jail process if running on Linux.
	isJailed := Jail()

	// If in jail, restart to be able to potentially read and write the Let's Encrypt certificates.
	if isJailed && terminateIfCertificateExpires { // We don't need `&& runtime.GOOS == "linux"`, because isJailed can only be true under linux.
		timer := time.NewTimer(shortestDuration)
		log.Printf("Set timer to expire in %s.\n", shortestDuration)

		log.Println("Serving files ...")

		// Wait for the timer to expire.
		<-timer.C

		// Close both server.
		terminateServer(httpServer, httpsServer)
	}

	// Wait for the wait group to reach zero.
	// This will happen when both the HTTP and the HTTPS server terminate.
	wgServerClosed.Wait()

	//
	// ========
	// BOTH SERVER HAVE CLOSED
	// ========
	//

	log.Println("Server terminated.")

	os.Exit(0)
}

// terminateServer shuts down the given servers with a timeout of 10 seconds.
//
// This function calls the http.Server.Shutdown() method for each server and passes in
// a context with a timeout. If the server has not completed shutdown by the end of the
// timeout, the context is cancelled and the server is terminated immediately.
func terminateServer(servers ...*http.Server) {
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

// TODO: Test if Let's Encrypt CRASHES, if it is unable to store its certificates to the file system.
// TODO: Also store the self signed certificates for the allowed self signed domains.
