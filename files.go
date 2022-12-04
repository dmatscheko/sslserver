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
			return nil
		}
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		trimmedPath := strings.TrimPrefix(path, dir)
		log.Println("Caching file:", trimmedPath)
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
	// The root is "/index.html".
	if path == "/" {
		path = "/index.html"
	}
	// Make the path safe to use with the os.Open function.
	path = filepath.Clean(path)
	// Check if the file has already been read and cached.
	data, ok := fileCache[path]
	if !ok {
		log.Println("File not found:", path)
		http.NotFound(w, r)
		return
	}

	// Write the file contents to the HTTP response.
	http.ServeContent(w, r, path, time.Time{}, bytes.NewReader(data)) // TODO: change time to file date and also cache this
}
