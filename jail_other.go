//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package main

import (
	"log"
	"os"
)

// enterJail on platforms without chroot/setuid (notably Windows) confines
// what it can: it changes the working directory into the jail and clears
// the environment. Anything stronger (a restricted process token, a job
// object) would need golang.org/x/sys/windows and considerably more code.
func enterJail(dir string) bool {
	if err := os.Chdir(dir); err != nil {
		log.Fatal("jail: ", err)
	}
	os.Clearenv()
	log.Println("Warning: no chroot or privilege drop on this platform; cleared the environment and changed the working directory to", dir)
	return false
}
