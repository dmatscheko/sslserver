package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

// The file cache is filled once at startup, before the process jails itself,
// and is strictly read-only afterwards — so it needs no locking.
type cacheEntry struct {
	data    []byte
	gzip    []byte // precompressed variant, nil when compression doesn't pay off
	etag    string // content hash, served as the ETag validator
	modTime time.Time
}

var fileCache = make(map[string]cacheEntry)

// diskRoot is what "domain/url/path" gets resolved against for disk reads:
// "/" once the process is chrooted into the web root, the absolute web root
// path when not chrooted, and "" when disk access is disabled entirely.
var diskRoot string

// fillCache loads every file in the web root up to the configured size
// limits into memory, keeps a gzipped variant of everything that shrinks
// by at least 10%, and records a content hash for ETag validation. Cache
// keys look like "example.com/css/site.css".
func fillCache() error {
	var files, kilobytes, gzipped, tooLarge, overTotal int
	var total int64
	root := config.WebRootDirectory
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Println("Warning: skipping unreadable path:", err)
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") && !config.dotNames[d.Name()] && p != root {
			// Dot names outside serve-dot-names are never served (see
			// cleanRequestPath), so don't cache them either.
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			if !d.IsDir() {
				log.Println("Ignoring special file or symlink:", p)
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		skip := ""
		if info.Size() > config.MaxCacheableFileSize {
			tooLarge++
			skip = "too large to cache"
		} else if config.MaxTotalCacheSize > 0 && total+info.Size() > config.MaxTotalCacheSize {
			overTotal++
			skip = "cache is full (max-total-cache-size)"
		}
		if skip != "" {
			if !config.ServeFilesNotInCache {
				log.Printf("Warning: %s, will NOT be served: %s", skip, p)
			}
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		entry := cacheEntry{data: data, etag: hex.EncodeToString(sum[:16]), modTime: info.ModTime()}
		// Precompress files of a known type when it saves at least 10%.
		if ct := mime.TypeByExtension(filepath.Ext(p)); ct != "" && len(data) >= 256 {
			if gz := gzipBytes(data); len(gz)*10 <= len(data)*9 {
				entry.gzip = gz
				gzipped++
			}
		}
		fileCache[filepath.ToSlash(rel)] = entry
		total += int64(len(data) + len(entry.gzip))
		files++
		kilobytes += (len(data) + 1023) / 1024
		return nil
	})
	log.Printf("Cached %d files (%d KiB, %d with gzip variant); skipped: %d larger than %d bytes, %d over the total cache size",
		files, kilobytes, gzipped, tooLarge, config.MaxCacheableFileSize, overTotal)
	return err
}

func gzipBytes(data []byte) []byte {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zw.Write(data)
	zw.Close()
	return buf.Bytes()
}

// serveFiles handles every HTTPS request: virtual host chosen by the Host
// header, content from the startup cache, larger files from disk when the
// configuration keeps disk access enabled.
func serveFiles(w http.ResponseWriter, r *http.Request) {
	if config.LogRequests {
		log.Printf("Request: %s %s %s%s", r.RemoteAddr, r.Method, r.Host, r.URL.Path)
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain, err := requestDomain(r.Host)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	urlPath, ok := cleanRequestPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}

	if config.ServerName != "" {
		w.Header().Set("Server", config.ServerName)
	}
	for name, value := range headersFor(domain) {
		if value == "" {
			continue
		}
		if r.TLS == nil && name == "Strict-Transport-Security" {
			continue // HSTS is meaningless (and misleading) over plain HTTP
		}
		w.Header().Set(name, value)
	}

	key := domain + urlPath
	if e, ok := fileCache[key]; ok {
		if ct := mime.TypeByExtension(path.Ext(urlPath)); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		body, etag := e.data, e.etag
		if e.gzip != nil {
			w.Header().Set("Vary", "Accept-Encoding")
			if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				// A compressed response is a different representation and
				// therefore gets a different ETag.
				body, etag = e.gzip, e.etag+"-gz"
				w.Header().Set("Content-Encoding", "gzip")
			}
		}
		w.Header().Set("ETag", `"`+etag+`"`)
		http.ServeContent(w, r, urlPath, e.modTime, bytes.NewReader(body))
		return
	}
	// A directory URL without trailing slash: redirect to the canonical form.
	if _, ok := fileCache[key+"/index.html"]; ok {
		q := ""
		if r.URL.RawQuery != "" {
			q = "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, urlPath+"/"+q, http.StatusMovedPermanently)
		return
	}
	if diskRoot == "" {
		http.NotFound(w, r)
		return
	}

	// Not cached (too large, or created after startup): serve from disk.
	f, err := os.Open(filepath.Join(diskRoot, filepath.FromSlash(key)))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	if info, err := f.Stat(); err == nil && info.Mode().IsRegular() {
		http.ServeContent(w, r, urlPath, info.ModTime(), f)
	} else {
		http.NotFound(w, r)
	}
}

// headersFor returns the effective response headers for a domain: the
// global set, or the per-domain merge precomputed from `domains`.
func headersFor(domain string) map[string]string {
	if h, ok := config.domainHeaders[domain]; ok {
		return h
	}
	return config.HttpHeaders
}

// serveHTTPFallback handles plain-HTTP requests that are not ACME
// challenges: domains configured with serve-http get their real content,
// everything else is redirected to HTTPS.
func serveHTTPFallback(w http.ResponseWriter, r *http.Request) {
	if domain, err := requestDomain(r.Host); err == nil && config.serveHTTP[domain] {
		serveFiles(w, r)
		return
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusFound)
}

// requestDomain validates the Host header against the domain whitelist and
// returns the web root subdirectory to serve — for a www alias that is the
// aliased domain's directory.
func requestDomain(host string) (string, error) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	name, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", err
	}
	dir, ok := config.domainDir[name]
	if !ok {
		return "", fmt.Errorf("unknown domain %q", name)
	}
	return dir, nil
}

// cleanRequestPath normalizes the URL path, rejects dot files and dot
// directories (except the serve-dot-names entries), and turns directory
// requests into their index.html.
func cleanRequestPath(p string) (string, bool) {
	dir := strings.HasSuffix(p, "/")
	p = path.Clean("/" + p)
	for _, segment := range strings.Split(p[1:], "/") {
		if strings.HasPrefix(segment, ".") && !config.dotNames[segment] {
			return "", false
		}
	}
	if dir || p == "/" {
		if p == "/" {
			p = ""
		}
		p += "/index.html"
	}
	return p, true
}

// hardenWebRoot makes the web root world-readable but read-only (files
// 0444, directories 0555) and, with chown-web-root, transfers ownership of
// everything to root. Ownership is what makes read-only stick: the owner
// of a file may always chmod it back to writable, so content owned by the
// jail user would not really be immutable for the serving process.
// Symlinks and special files are left alone (chmod would follow a symlink
// to its target, possibly outside the web root). Failures are only warned
// about — content that stays unreadable is skipped by fillCache with its
// own warning.
func hardenWebRoot(dir string) {
	chown := config.ChownWebRoot && os.Geteuid() == 0
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Println("Warning: cannot access:", err)
			return nil
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil
		}
		if chown {
			if err := os.Chown(p, 0, 0); err != nil {
				log.Println("Warning: cannot chown:", err)
			}
		}
		mode := os.FileMode(0444)
		if d.IsDir() {
			mode = 0555
		}
		if err := os.Chmod(p, mode); err != nil {
			log.Println("Warning: cannot chmod:", err)
		}
		return nil
	})
}
