//go:build linux
// +build linux

// Needs Go 1.16+!
// Prior to the release of Go 1.16 in 2021, the `syscall.Setuid()` function
// did not work reliably on Linux to drop the privilege of a setuid-root
// Go program. The issue was reported in 2011 but was not resolved until
// the release of Go 1.16. With Go 1.16 and later, `syscall.Setuid()` can be
// used to drop setuid-root privilege in native Go and when using CGo with
// the assistance of glibc's `nptl:setxid` mechanism.

package main

import (
	"log"
	"os"
	"syscall"

	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// Jail drops the privileges of the process and restricts it to the specified
// directory. It returns true to indicate that the program is now in a jail.
func Jail() bool {
	dirName := "./jail"

	// Look up the user ID of the "nobody" user.
	var uid int
	var gid int
	user := Getpwnam("nobody")
	if user == nil {
		log.Printf("Error looking up UID and GID for `nobody`. Falling back to 65534 for both.")
		uid = 65534
		gid = 65534
	} else {
		uid = user.UID
		gid = user.GID
	}

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
	err = syscall.Chroot(".")
	if err != nil {
		log.Fatal("Chroot: ", err)
	}

	log.Printf("Dropping rights...")

	// Drop all UID and GID rights of the process.
	err = syscall.Setregid(gid, gid)
	if err != nil {
		log.Fatalf("failed to drop REGID rights: %v", err)
	}
	err = syscall.Setreuid(uid, uid)
	if err != nil {
		log.Fatalf("failed to drop REUID rights: %v", err)
	}

	// Drop any privilege a process might have (including for root,
	// but note root 'owns' a lot of system files so a cap-limited
	// root can still do considerable damage to a running system).
	old := cap.GetProc()
	empty := cap.NewSet()
	if err := empty.SetProc(); err != nil {
		log.Fatalf("failed to drop privilege: %q -> %q: %v", old, empty, err)
	}
	now := cap.GetProc()
	if cf, _ := now.Cf(empty); cf != 0 {
		log.Fatalf("failed to fully drop privilege: have=%q, wanted=%q", now, empty)
	}

	// Try not to have too many things in memory.
	os.Clearenv()

	// Return true because the process is now in a jail.
	return true
}
