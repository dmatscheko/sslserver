package main

import (
	"bytes"
	"io/fs"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A map to store the contents of the files that have been served by the web
// server. The map keys are the file paths, and the values are the contents of
// the files.
type CacheEntry struct {
	File    []byte
	ModTime time.Time
}

var fileCache = make(map[string]CacheEntry)

// fillCache reads all files in the given directory and its subdirectories
// and stores their contents in the cache.
func fillCache(dir string) error {
	dir = filepath.Clean(dir)
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return err
		}

		// Get the path without the web root directory for logging.
		trimmedPath := strings.TrimPrefix(path, dir)

		// Get the file size in bytes.
		size := info.Size()
		if size > config.MaxCacheableFileSize {
			// File is to large for caching.
			log.Println(" Warning, file too large for caching:", trimmedPath)
			return nil
		}

		data, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		log.Println(" ", trimmedPath)
		fileCache[trimmedPath] = CacheEntry{File: data, ModTime: info.ModTime()}
		return nil
	})
}

// The serveFiles function is used as the handler for the "/" URL pattern.
// It reads the contents of the requested file from disk (or from the cache if
// it has already been read), and writes the contents to the HTTP response.
func serveFiles(w http.ResponseWriter, r *http.Request) {
	// Get the file path from the URL.
	path := r.URL.Path

	// Get the IP address of the client.
	clientIP := r.RemoteAddr
	if config.LogRequests {
		log.Println("Request:", clientIP, "", path)
	}

	// The root is "/index.html".
	if path == "/" {
		path = "/index.html"
	}
	// Make the path safe to use with the os.Open function.
	path = filepath.Clean(path)

	// Check if the file has already been read and cached.
	entry, isCached := fileCache[path]

	// Try to open the file on the disk and read the file info.
	if config.ServeFilesNotInCache {
		cacheAgain := false
		var info fs.FileInfo

		pathOnFileSystem := filepath.Join(config.WebRootDirectory, path)
		file, err := os.Open(pathOnFileSystem)
		if err != nil {
			// If the file is cached, it does not matter that it can't be opened.
			if !isCached {
				log.Println("File not found:", path)
				http.NotFound(w, r)
				return
			}
		} else {
			defer file.Close()

			// Get the file info.
			info, err = file.Stat()
			if err != nil {
				// If the file is cached, it does not matter that the stats can't be read.
				if !isCached {
					log.Println("File not found:", path)
					http.NotFound(w, r)
					return
				}
			} else {
				if info.ModTime().After(entry.ModTime) {
					cacheAgain = true
				}
			}
		}

		// If the file is not already cached, or there is a newer one on the disk, read it.
		if !isCached || cacheAgain {
			if info == nil { // Info is nil, when the file could not be opened correctly.
				log.Println("File not found:", path)
				http.NotFound(w, r)
				return
			}

			// Get the file size in bytes.
			size := info.Size()
			if size > config.MaxCacheableFileSize {
				// Serving large file contents to the HTTP response.
				addHeader(w)
				http.ServeContent(w, r, path, info.ModTime(), file)
				return
			}

			data, err := ioutil.ReadAll(file)
			if err != nil {
				log.Println("Could not read file:", path)
				http.NotFound(w, r)
			}

			// Cache the file contents in memory.
			log.Println("Updating new file into cache:", path)
			entry = CacheEntry{File: data, ModTime: info.ModTime()}
			fileCache[path] = entry
		}
	} else if !isCached {
		log.Println("File not found:", path)
		http.NotFound(w, r)
		return
	}

	// Write the file contents to the HTTP response.
	addHeader(w)
	http.ServeContent(w, r, path, entry.ModTime, bytes.NewReader(entry.File))
}

// addHeader adds the basic HTTP header.
func addHeader(w http.ResponseWriter) {
	// w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.Header().Set("Content-Security-Policy", "script-src 'self'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	/*
		// The server header is not needed.
		w.Header().Set("Server", "dma-srv")
		// The contenttype is added by ServeContent()
		w.Header().Set("Content-Type", contenttype)
		// Cache header are added by ServeContent()
		if cache {
			w.Header().Set("Cache-Control", "private, max-age=31536000")
		} else {
			w.Header().Set("Cache-control", "no-cache")
			w.Header().Set("Cache-control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}
	*/
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
