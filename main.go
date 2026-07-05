// A static HTTPS file server with automatic Let's Encrypt certificates and
// privilege separation: the parent process keeps all disk access (certificate
// cache, log file) and supervises the child, which binds the ports, jails
// itself and serves. The child reaches the certificate cache only through a
// small RPC protocol on its stdin/stdout; its stderr carries its log output.
package main

import (
	"flag"
	"log"
	"os"
)

func main() {
	configPath := flag.String("config", "", "path to the config file (default: config.yml next to the executable, created if missing)")
	child := flag.Bool("child", false, "internal: run as the jailed server child")
	flag.Parse()

	if *child {
		// The child talks RPC on stdout, so all of its logging must go to
		// stderr, which the parent forwards into the shared log.
		log.SetOutput(os.Stderr)
		log.SetPrefix("C ")
	} else {
		log.SetPrefix("P ")
	}

	if err := loadConfig(*configPath); err != nil {
		log.Fatal(err)
	}

	if *child {
		runChild()
	} else {
		runParent()
	}
}
