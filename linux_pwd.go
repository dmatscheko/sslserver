//go:build linux
// +build linux

// This file is licensed under the MIT license.

// It wraps the system password functions `getpwnam(3)` and `getpwuid()` and
// is mostly a copy from https://github.com/nogproject/nog/blob/master/backend/pkg/pwd/pwd.go.
package main

/*
#include <sys/types.h>
#include <pwd.h>
#include <stdlib.h>
*/
import "C"

import (
	"sync"
	"unsafe"
)

// Passwd is the Go type that corresponds to the C `struct passwd` defined in
// `pwd.h`; see man page `getpwnam(3)`.
type Passwd struct {
	// Name is the user's login name.
	Name string
	// Passwd is the user's encrypted password.
	Passwd string
	// UID is the user's ID.
	UID int
	// GID is the user's group ID.
	GID int
	// Gecos is the user's login information.
	Gecos string
	// Dir is the user's home directory.
	Dir string
	// Shell is the user's default shell.
	Shell string
}

// newPasswdFromC creates a new Passwd instance from a C `struct_passwd`.
func newPasswdFromC(c *C.struct_passwd) *Passwd {
	if c == nil {
		return nil
	}
	return &Passwd{
		Name:   C.GoString(c.pw_name),
		Passwd: C.GoString(c.pw_passwd),
		UID:    int(c.pw_uid),
		GID:    int(c.pw_uid),
		Gecos:  C.GoString(c.pw_gecos),
		Dir:    C.GoString(c.pw_dir),
		Shell:  C.GoString(c.pw_shell),
	}
}

// mu is a mutex that protects access to the `getpwnam` and `getpwuid` functions.
// It serializes calls to C functions that return statically allocated data
// that is overwritten in the next call. The mutex must be held locked until
// the data has been copied to Go variables.
var mu = sync.Mutex{}

// Getpwnam retrieves a user's password information by login name; see man page `getpwnam(3)`.
func Getpwnam(name string) *Passwd {
	// Convert the login name to a C string.
	cName := C.CString(name)
	// Defer the freeing of the C string memory.
	defer C.free(unsafe.Pointer(cName))
	// Lock the mutex to prevent race conditions.
	mu.Lock()
	// Defer unlocking the mutex.
	defer mu.Unlock()
	// Call `getpwnam` and return the result as a Passwd instance.
	return newPasswdFromC(C.getpwnam(cName))
}

// Getpwuid retrieves a user's password information by user ID; see man page `getpwnam(3)`.
func Getpwuid(uid int) *Passwd {
	// Lock the mutex to prevent race conditions.
	mu.Lock()
	// Defer unlocking the mutex.
	defer mu.Unlock()
	// Call `getpwuid` and return the result as a Passwd instance.
	return newPasswdFromC(C.getpwuid(C.uint(uid)))
}
