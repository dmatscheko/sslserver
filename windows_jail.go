//go:build windows
// +build windows

package main

import (
	"log"
	"os"
)

func Jail() bool {
	dirName := "./jail"

	// Check if the directory exists.
	if _, err := os.Stat(dirName); os.IsNotExist(err) {
		// Create the directory if it doesn't exist.
		if err := os.Mkdir(dirName, 0100); err != nil {
			log.Fatal(err)
		}
	}

	// Change the directory permissions to only "x".
	err := os.Chmod(dirName, 0100)
	if err != nil {
		log.Fatal(err)
	}
	// Change the working directory to dirName.
	err = os.Chdir(dirName)
	if err != nil {
		log.Fatal("Chdir: ", err)
	}
	// Change the root directory to dirName.
	// err = syscall.Chroot(".")            // THIS IS NOT POSSIBLE WITH WINDOWS
	// if err != nil {
	//	log.Fatal("Chroot: ", err)
	// }

	// Try not to have too many things in memory.
	os.Clearenv()

	return false // False, because this is no jail.
}
