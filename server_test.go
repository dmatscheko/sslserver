package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func withTestConfig(t *testing.T) {
	t.Helper()
	old := config
	t.Cleanup(func() { config = old })
	config = defaultConfig()
}

func TestCleanRequestPath(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"/", "/index.html", true},
		{"/sub/", "/sub/index.html", true},
		{"/a/b.css", "/a/b.css", true},
		{"/a/../b.css", "/b.css", true},
		{"/../../etc/passwd", "/etc/passwd", true}, // resolves inside the web root
		{"/a/..", "/index.html", true},
		{"//a//b.js", "/a/b.js", true},
		{"/.git/config", "", false},
		{"/a/.hidden", "", false},
		{"/a/..%2f", "", false}, // a literal dot-prefixed segment is rejected too
	}
	for _, c := range cases {
		got, ok := cleanRequestPath(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("cleanRequestPath(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestRequestDomain(t *testing.T) {
	withTestConfig(t)
	config.allDomains = map[string]bool{"example.com": true, "127.0.0.1": true}

	for host, want := range map[string]string{
		"example.com":      "example.com",
		"EXAMPLE.COM":      "example.com",
		"example.com:8443": "example.com",
		"127.0.0.1:443":    "127.0.0.1",
	} {
		if got, err := requestDomain(host); err != nil || got != want {
			t.Errorf("requestDomain(%q) = %q, %v; want %q", host, got, err, want)
		}
	}
	for _, host := range []string{"evil.com", "", "..", "example.com.", "sub.example.com"} {
		if got, err := requestDomain(host); err == nil {
			t.Errorf("requestDomain(%q) = %q, want error", host, got)
		}
	}
}

// The Let's Encrypt whitelist must be the web root subdirectories MINUS the
// self-signed domains (this subtraction was broken in the old server).
func TestCheckConfigDomainSplit(t *testing.T) {
	withTestConfig(t)
	dir := t.TempDir()
	for _, d := range []string{"example.com", "localhost"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0755); err != nil {
			t.Fatal(err)
		}
	}
	config.WebRootDirectory = dir
	config.CertificateCacheDirectory = t.TempDir()
	config.LogFile = ""

	if err := checkConfig(); err != nil {
		t.Fatal(err)
	}
	if len(config.letsEncryptDomains) != 1 || config.letsEncryptDomains[0] != "example.com" {
		t.Errorf("letsEncryptDomains = %v, want [example.com]", config.letsEncryptDomains)
	}
	for _, d := range []string{"example.com", "localhost", "127.0.0.1"} {
		if !config.allDomains[d] {
			t.Errorf("allDomains is missing %q", d)
		}
	}
}

func TestLoadConfigStrictKeys(t *testing.T) {
	withTestConfig(t)
	path := filepath.Join(t.TempDir(), "config.yml")

	os.WriteFile(path, []byte("no-such-option: 1\n"), 0644)
	if err := loadConfig(path); err == nil {
		t.Error("want error for unknown config key")
	}

	os.WriteFile(path, []byte("server-name: test\n"), 0644)
	if err := loadConfig(path); err != nil {
		t.Errorf("valid config rejected: %v", err)
	} else if config.ServerName != "test" {
		t.Errorf("ServerName = %q, want test", config.ServerName)
	}
}

func TestCheckConfigRejectsNestedPaths(t *testing.T) {
	withTestConfig(t)
	config.WebRootDirectory = t.TempDir()
	config.CertificateCacheDirectory = filepath.Join(config.WebRootDirectory, "certcache")
	if err := checkConfig(); err == nil {
		t.Error("want error for certificate cache inside the web root")
	}
}

// Full round trip of the certificate cache RPC through in-memory pipes.
func TestCertCacheRPC(t *testing.T) {
	withTestConfig(t)
	config.CertificateCacheDirectory = t.TempDir()

	reqR, reqW := io.Pipe()   // child stdout -> parent
	respR, respW := io.Pipe() // parent -> child stdin
	go serveCertCache(reqR, respW)
	cache := &rpcCache{enc: gob.NewEncoder(reqW), dec: gob.NewDecoder(respR)}
	ctx := context.Background()

	if _, err := cache.Get(ctx, "missing"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get(missing) = %v, want ErrCacheMiss", err)
	}
	if err := cache.Put(ctx, "example.com", []byte("cert-data")); err != nil {
		t.Fatal(err)
	}
	if got, err := cache.Get(ctx, "example.com"); err != nil || !bytes.Equal(got, []byte("cert-data")) {
		t.Fatalf("Get = %q, %v; want cert-data", got, err)
	}
	if err := cache.Delete(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(ctx, "example.com"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get after Delete = %v, want ErrCacheMiss", err)
	}
}

func TestMakeSelfSigned(t *testing.T) {
	withTestConfig(t)
	cert, err := makeSelfSigned("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Leaf.DNSNames) != 1 || cert.Leaf.DNSNames[0] != "example.com" {
		t.Errorf("DNSNames = %v, want [example.com]", cert.Leaf.DNSNames)
	}
	cert, err = makeSelfSigned("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Leaf.IPAddresses) != 1 || cert.Leaf.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("IPAddresses = %v, want [127.0.0.1]", cert.Leaf.IPAddresses)
	}
}

func TestRotatingWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	w, err := openRotatingWriter(path, 100, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	line := bytes.Repeat([]byte("x"), 59)
	for i := 0; i < 4; i++ {
		if _, err := w.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{path, path + ".1"} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if info.Size() != 59 && info.Size() != 118 {
			t.Errorf("%s has unexpected size %d", p, info.Size())
		}
	}
}

func TestRotatingWriterMaxAge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	old, fresh := path+".1", path+".2"
	for _, p := range []string{old, fresh} {
		if err := os.WriteFile(p, []byte("rotated"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}

	// maxAge 0 must keep everything.
	if _, err := openRotatingWriter(path, 100, 3, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); err != nil {
		t.Error("maxAge 0 must not delete rotated logs")
	}

	// With a maxAge, only files older than it are deleted.
	if _, err := openRotatingWriter(path, 100, 3, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("rotated log older than maxAge should have been deleted")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("rotated log younger than maxAge should have been kept")
	}
}
