package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"log"
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
	modTime time.Time
}

var fileCache = make(map[string]cacheEntry)

// diskRoot is what "domain/url/path" gets resolved against for disk reads:
// "/" once the process is chrooted into the web root, the absolute web root
// path when not chrooted, and "" when disk access is disabled entirely.
var diskRoot string

// fillCache loads every file in the web root up to the configured size
// limit into memory. Cache keys look like "example.com/css/site.css".
func fillCache() error {
	var files, kilobytes, tooLarge int
	root := config.WebRootDirectory
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Println("Warning: skipping unreadable path:", err)
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
		if info.Size() > config.MaxCacheableFileSize {
			tooLarge++
			if !config.ServeFilesNotInCache {
				log.Println("Warning: too large to cache, will NOT be served:", p)
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
		fileCache[filepath.ToSlash(rel)] = cacheEntry{data, info.ModTime()}
		files++
		kilobytes += (len(data) + 1023) / 1024
		return nil
	})
	log.Printf("Cached %d files (%d KiB); %d larger than %d bytes", files, kilobytes, tooLarge, config.MaxCacheableFileSize)
	return err
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
	for name, value := range config.HttpHeaders {
		if value != "" {
			w.Header().Set(name, value)
		}
	}

	key := domain + urlPath
	if e, ok := fileCache[key]; ok {
		http.ServeContent(w, r, urlPath, e.modTime, bytes.NewReader(e.data))
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

// requestDomain validates the Host header against the domain whitelist and
// returns its punycoded form, which is also the web root subdirectory name.
func requestDomain(host string) (string, error) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	name, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", err
	}
	if !config.allDomains[name] {
		return "", fmt.Errorf("unknown domain %q", name)
	}
	return name, nil
}

// cleanRequestPath normalizes the URL path, rejects dot files and dot
// directories, and turns directory requests into their index.html.
func cleanRequestPath(p string) (string, bool) {
	dir := strings.HasSuffix(p, "/")
	p = path.Clean("/" + p)
	if strings.Contains(p, "/.") {
		return "", false
	}
	if dir || p == "/" {
		if p == "/" {
			p = ""
		}
		p += "/index.html"
	}
	return p, true
}

// setPermissions makes the web root world-readable but read-only
// (files 0444, directories 0555), so the jailed child can read it but not
// write to it. Failures are only warned about — content that stays
// unreadable is skipped by fillCache with its own warning.
func setPermissions(dir string) {
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Println("Warning: cannot access:", err)
			return nil
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
