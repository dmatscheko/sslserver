package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

// A map to store the contents of the files that have been served by the web
// server. The map keys are the file paths, and the values are the contents of
// the files.
type CacheEntry struct {
	FileContent []byte    // Content of file that is kept in memory
	FilePointer *os.File  // Pointer to file that is too large and needs to be read from disk
	ModTime     time.Time // Modification time of the file
}

var fileCache = make(map[string]CacheEntry)

// fillCache reads all files in the given directory and its subdirectories
// and stores their contents in the cache.
// TODO: Either don't use fillCache or first read all main folders (domains) and then read in them, following symlinks, but only after being jailed.
func fillCache(dir string) error {
	dir = filepath.Clean(dir)
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		path2, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		if path != path2 {
			log.Printf("Directory is symlink - not supported yet: %s -> %s\n", path, path2)
			return nil
		}

		// Get the path without the web root directory
		trimmedPath := strings.TrimPrefix(path, config.WebRootDirectory)
		trimmedPath = strings.TrimPrefix(trimmedPath, "/")

		// Get the file size in bytes
		size := info.Size()
		if size > config.MaxCacheableFileSize {
			// File is to large for caching
			log.Println(" Warning, file too large for caching:", trimmedPath)
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		log.Println(" ", trimmedPath)
		fileCache[trimmedPath] = CacheEntry{FileContent: data, ModTime: info.ModTime()}
		return nil
	})
}

// for serveFiles
var matchPath = regexp.MustCompile(`^(/[a-zA-Z0-9_-]+)+(\.[a-zA-Z0-9]+)+$`).MatchString

// The serveFiles function is used as the handler for the "/" URL pattern.
// It reads the contents of the requested file from disk (or from the cache if
// it has already been read), and writes the contents to the HTTP response.
func serveFiles(w http.ResponseWriter, r *http.Request) {
	// Extract URL path and domain from the request
	urlPath := r.URL.Path
	domain := r.Host
	// Get the IP address of the client.
	clientIP := r.RemoteAddr

	if config.LogRequests {
		log.Println("Request:", clientIP, "", urlPath)
	}

	domain, err := validateDomain(domain)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	urlPath, err = validateAndCleanPath(urlPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Prepend domain and webroot to the URL path to get the file path
	filePath := filepath.FromSlash(domain + urlPath)

	entry, err := getFileEntry(filePath, domain+urlPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Write the file contents to the HTTP response.
	addHeaders(w)
	if entry.FilePointer != nil {
		http.ServeContent(w, r, urlPath, entry.ModTime, entry.FilePointer)
		entry.FilePointer.Close()
	} else {
		http.ServeContent(w, r, urlPath, entry.ModTime, bytes.NewReader(entry.FileContent))
	}
}

func validateDomain(domain string) (string, error) {
	// Set default domain if none provided
	if domain == "" {
		return "nodomain", nil
	}

	// Check if the domain is allowed
	asciiDomain, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("invalid domain: %v", err)
	}
	if !config.allDomains[asciiDomain] {
		return "", errors.New("domain not allowed")
	}

	return asciiDomain, nil
}

func validateAndCleanPath(urlPath string) (string, error) {
	// Clean the URL path for security
	if urlPath != path.Clean(urlPath) {
		return "", errors.New("invalid URL path")
	}

	// Set default file to index.html if URL path is root
	if urlPath == "/" {
		urlPath = "/index.html"
	}

	// Check if the URL path matches the expected file pattern
	if !matchPath(urlPath) {
		return "", errors.New("invalid URL path pattern")
	}

	return urlPath, nil
}

func getFileEntry(filePath, domainAndUrlPath string) (CacheEntry, error) {
	// Check if the file has already been read and cached
	entry, isCached := fileCache[filePath]

	// Try to open the file if serving files not in cache
	if config.ServeFilesNotInCache {
		file, err := os.Open(filePath)
		if err != nil {
			if isCached { // If the file is cached, it doesn't matter that it can't be opened (is the case if the webroot is outside the jail)
				log.Printf("Returning cached entry, cannot open file: %s", domainAndUrlPath)
				return entry, nil
			}
			return CacheEntry{}, fmt.Errorf("can't open file and not cached: %s", domainAndUrlPath)
		}
		// defer file.Close() // Don't always close the file descriptor in this func. It will sometimes be closed in serveFiles()

		info, err := file.Stat()
		if err != nil {
			// We don't return the file descriptor so we can close it
			file.Close()
			if isCached { // If the file is cached, it doesn't matter that the file info can't be read (is the case if the webroot is outside the jail)
				log.Printf("Returning cached entry, cannot read file info: %s", domainAndUrlPath)
				return entry, nil
			}
			return CacheEntry{}, fmt.Errorf("can't read file info and not cached: %s", domainAndUrlPath)
		}

		// Update cache if file modification time differs
		if !isCached || !info.ModTime().Equal(entry.ModTime) {
			if info.Size() > config.MaxCacheableFileSize {
				// Return large file as file descriptor (that needs to be closed)
				return CacheEntry{FilePointer: file, ModTime: info.ModTime()}, nil
			}

			// We don't return the file descriptor so we can close it
			defer file.Close()

			data, err := io.ReadAll(file)
			if err != nil {
				return CacheEntry{}, fmt.Errorf("can't read file content: %s", domainAndUrlPath)
			}

			log.Println("Updating cache with new file:", domainAndUrlPath)
			entry = CacheEntry{FileContent: data, ModTime: info.ModTime()}
			fileCache[filePath] = entry
		}
	} else if !isCached {
		return CacheEntry{}, fmt.Errorf("file not cached and reading from disk is disabled: %s", domainAndUrlPath)
	}

	return entry, nil
}

// addHeaders adds basic HTTP headers to the response.
func addHeaders(w http.ResponseWriter) {
	if config.ServerName != "" {
		w.Header().Set("Server", config.ServerName)
	}

	// Add common security headers
	if config.HttpHeaderXContentTypeOptions != "" {
		w.Header().Set("X-Content-Type-Options", config.HttpHeaderXContentTypeOptions)
	}
	if config.HttpHeaderStrictTransportSecurity != "" {
		w.Header().Set("Strict-Transport-Security", config.HttpHeaderStrictTransportSecurity)
	}
	if config.HttpHeaderContentSecurityPolicy != "" {
		w.Header().Set("Content-Security-Policy", config.HttpHeaderContentSecurityPolicy)
	}
	if config.HttpHeaderXFrameOptions != "" {
		w.Header().Set("X-Frame-Options", config.HttpHeaderXFrameOptions)
	}

	// TODO: make this configurable
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
}

func setPermissions(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			// Change the directory permissions to "rx".
			err := os.Chmod(path, 0555)
			return err
		}

		// Change the file permissions to "r".
		err = os.Chmod(path, 0444)
		if err != nil {
			return err
		}

		return nil
	})
}
