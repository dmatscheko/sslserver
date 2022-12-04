//go:build linux
// +build linux

package main

import (
	"log"
	"os"
	"syscall"
)

// Jail drops the privileges of the process and restricts it to the specified
// directory. It returns true to indicate that the program is now in a jail.
func Jail() bool {
	dirPath := "./jail"

	// Change the directory permissions to only "x".
	err := os.Chmod(dirPath, 0100)
	if err != nil {
		log.Fatal(err)
	}
	// Change the working directory to dirPath.
	err = os.Chdir(dirPath)
	if err != nil {
		log.Fatal("Chdir: ", err)
	}
	// Change the root directory to dirPath.
	err = syscall.Chroot(".")
	if err != nil {
		log.Fatal("Chroot: ", err)
	}

	// Set the group ID (GID) to 65534.
	err = syscall.Setgid(65534)
	if err != nil {
		log.Fatal("Setgid: ", err)
	}
	// Set the user ID (UID) to 65534.
	err = syscall.Setuid(65534)
	if err != nil {
		log.Fatal("Setuid: ", err)
	}

	// Return true because the process is now in a jail.
	return true
}
