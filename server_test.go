package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/gob"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"gopkg.in/yaml.v3"
)

func withTestConfig(t *testing.T) {
	t.Helper()
	old, oldCache := config, fileCache
	t.Cleanup(func() { config, fileCache = old, oldCache })
	config = defaultConfig()
	fileCache = map[string]cacheEntry{}
}

func TestCleanRequestPath(t *testing.T) {
	withTestConfig(t)
	config.dotNames = map[string]bool{".well-known": true}
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
		{"/.well-known/security.txt", "/.well-known/security.txt", true},
		{"/.well-known/", "/.well-known/index.html", true},
		{"/.well-known2/x.txt", "", false}, // only exact dot names are allowed
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
	config.domainDir = map[string]string{
		"example.com":     "example.com",
		"www.example.com": "example.com", // a www alias maps to the base directory
		"127.0.0.1":       "127.0.0.1",
	}

	for host, want := range map[string]string{
		"example.com":          "example.com",
		"EXAMPLE.COM":          "example.com",
		"example.com:8443":     "example.com",
		"www.example.com":      "example.com",
		"www.example.com:8443": "example.com",
		"127.0.0.1:443":        "127.0.0.1",
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
		if config.domainDir[d] != d {
			t.Errorf("domainDir is missing %q", d)
		}
	}
}

func TestCheckConfigWwwAlias(t *testing.T) {
	withTestConfig(t)
	dir := t.TempDir()
	for _, d := range []string{"example.com", "www.other.org"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0755); err != nil {
			t.Fatal(err)
		}
	}
	config.WebRootDirectory = dir
	config.CertificateCacheDirectory = t.TempDir()
	config.LogFile = ""
	config.WwwAlias = true

	if err := checkConfig(); err != nil {
		t.Fatal(err)
	}
	for host, wantDir := range map[string]string{
		"example.com":     "example.com",
		"www.example.com": "example.com",
		"www.other.org":   "www.other.org",
		"other.org":       "www.other.org",
		"www.localhost":   "localhost",
	} {
		if config.domainDir[host] != wantDir {
			t.Errorf("domainDir[%q] = %q, want %q", host, config.domainDir[host], wantDir)
		}
	}
	if _, ok := config.domainDir["www.127.0.0.1"]; ok {
		t.Error("IP addresses must not get a www alias")
	}
	if !config.selfSigned["www.localhost"] {
		t.Error("the alias of a self-signed domain must be self-signed too")
	}
	le := map[string]bool{}
	for _, d := range config.letsEncryptDomains {
		le[d] = true
	}
	for _, d := range []string{"example.com", "www.example.com", "other.org", "www.other.org"} {
		if !le[d] {
			t.Errorf("letsEncryptDomains is missing %q", d)
		}
	}
}

// The generated, commented config file must stay in sync with the defaults
// in the code — otherwise its "Default:" comments would lie.
func TestDefaultConfigFileMatchesDefaults(t *testing.T) {
	var fromFile ServerConfig
	dec := yaml.NewDecoder(strings.NewReader(defaultConfigFile))
	dec.KnownFields(true)
	if err := dec.Decode(&fromFile); err != nil {
		t.Fatal(err)
	}
	if want := defaultConfig(); !reflect.DeepEqual(fromFile, want) {
		t.Errorf("defaultConfigFile drifted from defaultConfig():\nfile:     %+v\ndefaults: %+v", fromFile, want)
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

// Aliases are prewarmed only when the cache already holds a certificate
// for them — under the plain key or the legacy "+rsa" key.
func TestCachedCertExists(t *testing.T) {
	withTestConfig(t)
	config.CertificateCacheDirectory = t.TempDir()
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	go serveCertCache(reqR, respW)
	m := &certManager{acme: &autocert.Manager{
		Cache: &rpcCache{enc: gob.NewEncoder(reqW), dec: gob.NewDecoder(respR)},
	}}
	ctx := context.Background()

	if m.cachedCertExists(ctx, "www.example.com") {
		t.Error("empty cache must report no certificate")
	}
	if err := m.acme.Cache.Put(ctx, "www.example.com", []byte("pem")); err != nil {
		t.Fatal(err)
	}
	if !m.cachedCertExists(ctx, "www.example.com") {
		t.Error("cached certificate not found under its plain key")
	}
	if err := m.acme.Cache.Put(ctx, "www.other.org+rsa", []byte("pem")); err != nil {
		t.Fatal(err)
	}
	if !m.cachedCertExists(ctx, "www.other.org") {
		t.Error("cached certificate not found under its +rsa key")
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

func TestFillCacheCompressionAndCap(t *testing.T) {
	withTestConfig(t)
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "localhost"), 0755)
	compressible := strings.Repeat("compress me please ", 200)
	os.WriteFile(filepath.Join(root, "localhost", "big.css"), []byte(compressible), 0644)
	os.WriteFile(filepath.Join(root, "localhost", "tiny.txt"), []byte("hi"), 0644)
	config.WebRootDirectory = root
	config.dotNames = map[string]bool{}

	if err := fillCache(); err != nil {
		t.Fatal(err)
	}
	e := fileCache["localhost/big.css"]
	if e.gzip == nil || len(e.gzip) >= len(e.data) {
		t.Errorf("compressible file should have a smaller gzip variant (data %d, gzip %d)", len(e.data), len(e.gzip))
	}
	if e.etag == "" {
		t.Error("cached entry has no etag")
	}
	if fileCache["localhost/tiny.txt"].gzip != nil {
		t.Error("tiny file should not get a gzip variant")
	}

	// With a tiny total cap only the small file fits.
	fileCache = map[string]cacheEntry{}
	config.MaxTotalCacheSize = 100
	if err := fillCache(); err != nil {
		t.Fatal(err)
	}
	if len(fileCache) != 1 || fileCache["localhost/tiny.txt"].data == nil {
		t.Errorf("cache cap: got %d entries, want only tiny.txt", len(fileCache))
	}
}

func TestServeCompressionAndETag(t *testing.T) {
	withTestConfig(t)
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "localhost"), 0755)
	content := strings.Repeat("body { color: red } ", 100)
	os.WriteFile(filepath.Join(root, "localhost", "site.css"), []byte(content), 0644)
	config.WebRootDirectory = root
	config.dotNames = map[string]bool{}
	config.domainDir = map[string]string{"localhost": "localhost"}
	if err := fillCache(); err != nil {
		t.Fatal(err)
	}

	get := func(encoding, ifNoneMatch string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://localhost/site.css", nil)
		req.TLS = &tls.ConnectionState{}
		if encoding != "" {
			req.Header.Set("Accept-Encoding", encoding)
		}
		if ifNoneMatch != "" {
			req.Header.Set("If-None-Match", ifNoneMatch)
		}
		rr := httptest.NewRecorder()
		serveFiles(rr, req)
		return rr
	}

	// Client with gzip support gets the compressed representation.
	rr := get("gzip, br", "")
	if rr.Header().Get("Content-Encoding") != "gzip" || rr.Header().Get("Vary") != "Accept-Encoding" {
		t.Errorf("want gzip encoding with Vary, got %q/%q", rr.Header().Get("Content-Encoding"), rr.Header().Get("Vary"))
	}
	etag := rr.Header().Get("ETag")
	if !strings.HasSuffix(etag, `-gz"`) {
		t.Errorf("gzip ETag = %s, want -gz suffix", etag)
	}
	zr, err := gzip.NewReader(rr.Body)
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := io.ReadAll(zr); string(body) != content {
		t.Error("gzip body does not decompress to the original content")
	}

	// A matching ETag revalidates with 304.
	if rr := get("gzip", etag); rr.Code != http.StatusNotModified {
		t.Errorf("If-None-Match: got %d, want 304", rr.Code)
	}

	// A client without gzip support gets the identity representation.
	rr = get("", "")
	if rr.Header().Get("Content-Encoding") != "" || rr.Body.String() != content {
		t.Error("identity response is wrong")
	}
	if got := rr.Header().Get("ETag"); strings.HasSuffix(got, `-gz"`) || got == "" {
		t.Errorf("identity ETag = %s", got)
	}
}

func TestServeHTTPFallback(t *testing.T) {
	withTestConfig(t)
	config.dotNames = map[string]bool{}
	config.domainDir = map[string]string{"plain.example": "plain.example", "secure.example": "secure.example"}
	config.serveHTTP = map[string]bool{"plain.example": true}
	fileCache = map[string]cacheEntry{
		"plain.example/index.html": {data: []byte("plain-ok"), etag: "x", modTime: time.Now()},
	}

	// serve-http domain: content over plain HTTP, but without HSTS.
	rr := httptest.NewRecorder()
	serveHTTPFallback(rr, httptest.NewRequest("GET", "http://plain.example/", nil))
	if rr.Code != http.StatusOK || rr.Body.String() != "plain-ok" {
		t.Errorf("serve-http: got %d %q", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must not be sent over plain HTTP")
	}

	// Everything else redirects to HTTPS, dropping the port.
	rr = httptest.NewRecorder()
	serveHTTPFallback(rr, httptest.NewRequest("GET", "http://secure.example:8080/x.html?q=1", nil))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "https://secure.example/x.html?q=1" {
		t.Errorf("redirect: got %d %q", rr.Code, rr.Header().Get("Location"))
	}
}

// A symlinked domain directory (www.example.com -> example.com) is served
// as an alias of its target; symlinks leaving the web root are ignored.
func TestCheckConfigSymlinkedDomain(t *testing.T) {
	withTestConfig(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "example.com"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("example.com", filepath.Join(dir, "www.example.com")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "outside.example")); err != nil {
		t.Fatal(err)
	}
	config.WebRootDirectory = dir
	config.CertificateCacheDirectory = t.TempDir()
	config.LogFile = ""

	if err := checkConfig(); err != nil {
		t.Fatal(err)
	}
	if config.domainDir["www.example.com"] != "example.com" {
		t.Errorf("domainDir[www.example.com] = %q, want example.com", config.domainDir["www.example.com"])
	}
	if _, ok := config.domainDir["outside.example"]; ok {
		t.Error("a symlink leaving the web root must not become a domain")
	}
	le := map[string]bool{}
	for _, d := range config.letsEncryptDomains {
		le[d] = true
	}
	if !le["www.example.com"] || le["outside.example"] {
		t.Errorf("letsEncryptDomains = %v", config.letsEncryptDomains)
	}
}

func TestCheckConfigDomainOverrides(t *testing.T) {
	withTestConfig(t)
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "example.com"), 0755)
	config.WebRootDirectory = dir
	config.CertificateCacheDirectory = t.TempDir()
	config.LogFile = ""
	config.WwwAlias = true
	config.Domains = map[string]DomainConfig{
		// Keyed by the alias: must apply to the directory domain.
		"www.example.com": {ServeHttp: true, HttpHeaders: map[string]string{"Content-Security-Policy": "custom"}},
	}
	if err := checkConfig(); err != nil {
		t.Fatal(err)
	}
	if !config.serveHTTP["example.com"] {
		t.Error("serve-http via alias key must apply to the directory domain")
	}
	h := config.domainHeaders["example.com"]
	if h["Content-Security-Policy"] != "custom" || h["X-Frame-Options"] != "DENY" {
		t.Errorf("per-domain headers not merged over globals: %v", h)
	}

	// An override for an unknown domain is a config error.
	config = defaultConfig()
	config.WebRootDirectory = dir
	config.CertificateCacheDirectory = t.TempDir()
	config.LogFile = ""
	config.Domains = map[string]DomainConfig{"unknown.example": {}}
	if err := checkConfig(); err == nil {
		t.Error("want error for a domains entry that matches no served domain")
	}
}

// hardenWebRoot must chmod regular files and directories, but leave
// symlinks alone — chmod would follow them to their target, which can live
// outside the web root.
func TestHardenWebRootSkipsSymlinks(t *testing.T) {
	withTestConfig(t)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	file := filepath.Join(root, "a.txt")
	os.WriteFile(file, []byte("x"), 0644)
	if err := os.Symlink(outside, filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}

	hardenWebRoot(root)

	if info, _ := os.Stat(file); info.Mode().Perm() != 0444 {
		t.Errorf("file mode = %o, want 0444", info.Mode().Perm())
	}
	if info, _ := os.Stat(root); info.Mode().Perm() != 0555 {
		t.Errorf("dir mode = %o, want 0555", info.Mode().Perm())
	}
	if info, _ := os.Stat(outside); info.Mode().Perm() != 0644 {
		t.Errorf("symlink target mode = %o, want untouched 0644", info.Mode().Perm())
	}
	os.Chmod(root, 0755) // let t.TempDir clean up
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
