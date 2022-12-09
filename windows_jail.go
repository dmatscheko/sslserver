//go:build windows
// +build windows

package main

import (
	"log"
	"os"
	"path/filepath"
)

func Jail(dir string) bool {
	// Make the path safe to use with the os.Open function.
	dir = filepath.Clean(dir)

	// Check if the directory exists.
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		// Create the directory if it doesn't exist.
		if err := os.MkdirAll(dir, 0555); err != nil {
			log.Fatal(err)
		}
	}

	log.Println("Setting file permissions for jail")
	// Set file permissions for jail.
	err := setPermissions(dir)
	if err != nil {
		log.Fatal("Could not set permissions:", err)
	}

	// Change the working directory to dir.
	err = os.Chdir(dir)
	if err != nil {
		log.Fatal("Chdir: ", err)
	}
	// Change the root directory to dir.
	// err = syscall.Chroot(".")            // THIS IS NOT POSSIBLE WITH WINDOWS
	// if err != nil {
	//	log.Fatal("Chroot: ", err)
	// }

	// Try not to have too many things in memory.
	os.Clearenv()

	return false // False, because this is no jail.
}
