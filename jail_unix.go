//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package main

import (
	"log"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// enterJail chroots into dir, drops root privileges to an unprivileged user
// and clears the environment. Requires Go 1.16+ on Linux: since then
// syscall.Set*id applies to all runtime threads, and changing the UID away
// from 0 also clears every capability set, so no libcap dance is needed. On
// macOS and the BSDs credentials are per-process anyway. Returns whether
// the process really ended up chrooted.
func enterJail(dir string) bool {
	if err := os.Chdir(dir); err != nil {
		log.Fatal("jail: ", err)
	}
	if os.Geteuid() != 0 {
		os.Clearenv()
		log.Println("Warning: not running as root, continuing WITHOUT chroot jail and privilege drop")
		return false
	}
	uid, gid := jailUser()

	if err := syscall.Chroot("."); err != nil {
		log.Fatal("jail: chroot: ", err)
	}
	if err := os.Chdir("/"); err != nil {
		log.Fatal("jail: ", err)
	}

	// Drop supplementary groups, then the group and user IDs. Setting the
	// real IDs also resets the saved IDs (POSIX), so there is no way back —
	// which the verification below proves.
	if err := syscall.Setgroups([]int{gid}); err != nil {
		log.Fatal("jail: setgroups: ", err)
	}
	if err := syscall.Setregid(gid, gid); err != nil {
		log.Fatal("jail: setregid: ", err)
	}
	if err := syscall.Setreuid(uid, uid); err != nil {
		log.Fatal("jail: setreuid: ", err)
	}

	// Verify the privileges are really gone: regaining root must fail.
	if err := syscall.Setuid(0); err == nil {
		log.Fatal("jail: process could regain root, aborting")
	}
	if syscall.Getuid() != uid || syscall.Getgid() != gid {
		log.Fatal("jail: dropping privileges failed")
	}

	os.Clearenv()
	log.Printf("Jailed into %s as uid=%d gid=%d", dir, uid, gid)
	return true
}

// jailUser returns the UID/GID to drop to: the first of the usual web and
// nobody users that exists, else the classic nobody IDs.
func jailUser() (int, int) {
	for _, name := range []string{"www", "www-data", "_www", "nobody"} {
		if u, err := user.Lookup(name); err == nil {
			uid, err1 := strconv.Atoi(u.Uid)
			gid, err2 := strconv.Atoi(u.Gid)
			if err1 == nil && err2 == nil {
				return uid, gid
			}
		}
	}
	log.Println("Warning: no unprivileged user found, using 65534")
	return 65534, 65534
}
