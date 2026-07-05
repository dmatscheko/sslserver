package main

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"gopkg.in/yaml.v3"
)

// The certificate cache RPC between child and parent: the child writes one
// gob-encoded cacheReq to its stdout and reads exactly one cacheResp from its
// stdin, so requests and responses stay in lockstep.
type cacheReq struct {
	Op   byte // 'g'et, 'p'ut, 'd'elete
	Name string
	Data []byte
}

type cacheResp struct {
	Data []byte
	Err  string // "" = ok, "miss" = autocert.ErrCacheMiss
}

// runParent starts the child and serves its certificate cache requests until
// the child exits. Terminating signals are forwarded to the child, which
// shuts down gracefully.
func runParent() {
	logDest := io.Writer(os.Stdout)
	if config.LogFile != "" {
		rot, err := openRotatingWriter(config.LogFile, 5<<20, 3, config.LogMaxAge)
		if err != nil {
			log.Fatal(err)
		}
		logDest = io.MultiWriter(os.Stdout, rot)
	}
	log.SetOutput(logDest)

	if out, err := yaml.Marshal(config); err == nil {
		log.Printf("Using config file %s:\n%s", configFile, out)
	}

	exe, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	child := exec.Command(exe, "-child", "-config", configFile)
	child.Stderr = logDest // the child's log lines already carry their own "C " prefix
	reqPipe, err := child.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	respPipe, err := child.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}
	if err := child.Start(); err != nil {
		log.Fatal(err)
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range sigc {
			log.Println("Forwarding signal to server:", s)
			child.Process.Signal(s)
		}
	}()

	serveCertCache(reqPipe, respPipe)

	if err := child.Wait(); err != nil {
		log.Println("Server exited:", err)
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() > 0 {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
	log.Println("Server terminated.")
}

// serveCertCache answers the child's certificate cache RPCs against the
// on-disk autocert cache until the child's stdout closes (= child exited).
func serveCertCache(r io.Reader, w io.Writer) {
	cache := autocert.DirCache(config.CertificateCacheDirectory)
	dec, enc := gob.NewDecoder(r), gob.NewEncoder(w)
	ctx := context.Background()
	for {
		var req cacheReq
		if err := dec.Decode(&req); err != nil {
			if !errors.Is(err, io.EOF) {
				log.Println("Certificate cache RPC read:", err)
			}
			return
		}
		var resp cacheResp
		var err error
		switch req.Op {
		case 'g':
			resp.Data, err = cache.Get(ctx, req.Name)
		case 'p':
			err = cache.Put(ctx, req.Name, req.Data)
			log.Println("Stored certificate data:", req.Name)
		case 'd':
			err = cache.Delete(ctx, req.Name)
		default:
			err = fmt.Errorf("unknown op %q", req.Op)
		}
		if errors.Is(err, autocert.ErrCacheMiss) {
			resp.Err = "miss"
		} else if err != nil {
			resp.Err = err.Error()
			log.Println("Certificate cache:", err)
		}
		if err := enc.Encode(&resp); err != nil {
			log.Println("Certificate cache RPC write:", err)
			return
		}
	}
}

// rotatingWriter appends to a log file and rotates it when it exceeds max
// bytes, keeping `keep` old files (file.1 … file.keep). Rotated-out files
// older than maxAge are deleted (0 = never). It is safe for concurrent use
// (the parent's logger and the child's stderr both write).
type rotatingWriter struct {
	mu     sync.Mutex
	path   string
	max    int64
	keep   int
	maxAge time.Duration
	f      *os.File
	size   int64
}

func openRotatingWriter(path string, max int64, keep int, maxAge time.Duration) (*rotatingWriter, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	w := &rotatingWriter{path: path, max: max, keep: keep, maxAge: maxAge, f: f, size: info.Size()}
	w.pruneOld()
	if maxAge > 0 {
		// Age out rotated files even during long stretches without rotation.
		go func() {
			for range time.Tick(time.Hour) {
				w.pruneOld()
			}
		}()
	}
	return w, nil
}

// pruneOld deletes rotated-out log files older than maxAge. It only ever
// touches the numbered files and reads immutable fields, so it needs no
// lock; racing a concurrent rotation is harmless.
func (w *rotatingWriter) pruneOld() {
	if w.maxAge <= 0 {
		return
	}
	for i := 1; i <= w.keep; i++ {
		p := fmt.Sprintf("%s.%d", w.path, i)
		if info, err := os.Stat(p); err == nil && time.Since(info.ModTime()) > w.maxAge {
			os.Remove(p)
		}
	}
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.size+int64(len(p)) > w.max {
		w.f.Close()
		os.Remove(fmt.Sprintf("%s.%d", w.path, w.keep))
		for i := w.keep; i > 1; i-- {
			os.Rename(fmt.Sprintf("%s.%d", w.path, i-1), fmt.Sprintf("%s.%d", w.path, i))
		}
		os.Rename(w.path, w.path+".1")
		f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return 0, err
		}
		w.f, w.size = f, 0
		w.pruneOld()
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}
