package main

import (
	"bytes"
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
var fileCache = make(map[string][]byte)

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
		fileCache[trimmedPath] = data
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
	data, ok := fileCache[path]
	if !ok {
		if !config.ServeFilesNotInCache {
			log.Println("File not found:", path)
			http.NotFound(w, r)
			return
		}

		// The file has not been cached, so read it from disk.
		pathOnFileSystem := filepath.Join(config.BaseDirectory, path)
		file, err := os.Open(pathOnFileSystem)
		if err != nil {
			log.Println("File not found:", path)
			http.NotFound(w, r)
			return
		}
		defer file.Close()

		// Get the file info.
		info, err := file.Stat()
		if err != nil {
			log.Println("File not found:", path)
			http.NotFound(w, r)
			return
		}

		// Get the file size in bytes.
		size := info.Size()
		if size > config.MaxCacheableFileSize {
			// Serving large file contents to the HTTP response.
			http.ServeContent(w, r, path, time.Time{}, file)
			return
		}

		data, err = ioutil.ReadAll(file)
		if err != nil {
			log.Println("Could not read file:", path)
			http.NotFound(w, r)
		}

		// Cache the file contents in memory.
		fileCache[path] = data
	}

	// Write the file contents to the HTTP response.
	http.ServeContent(w, r, path, time.Time{}, bytes.NewReader(data)) // TODO: change time to file date and also cache this
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
