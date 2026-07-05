package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"gopkg.in/yaml.v3"
)

// ServerConfig holds all settings. Every exported field can be set in the
// YAML config file; missing fields keep their defaults.
type ServerConfig struct {
	// Directory with one subdirectory per domain (virtual host) to serve.
	// All files in it are made world-readable and read-only at startup.
	WebRootDirectory string `yaml:"web-root-directory"`

	// Let's Encrypt account data and certificates are stored here. Only the
	// parent process touches it; it must not be inside the web root.
	CertificateCacheDirectory string `yaml:"certificate-cache-directory"`

	// E-mail for the Let's Encrypt account (expiry notices etc.).
	AcmeEmail string `yaml:"acme-email"`

	// Listen addresses; service names such as ":http" are allowed.
	HttpAddr  string `yaml:"http-addr"`
	HttpsAddr string `yaml:"https-addr"`

	// Domains that get a self-signed certificate instead of Let's Encrypt.
	// Domains found in the web root are also served under these names.
	SelfSignedDomains []string `yaml:"self-signed-domains"`

	// Value of the "Server" response header ("" = no header).
	ServerName string `yaml:"server-name"`

	// Response headers. Entries here are merged over the built-in defaults;
	// set a value to "" to disable a default header.
	HttpHeaders map[string]string `yaml:"http-headers"`

	// Renew or regenerate certificates that expire within this duration.
	CertificateExpiryRefreshThreshold time.Duration `yaml:"certificate-expiry-refresh-threshold"`

	MaxRequestTimeout  time.Duration `yaml:"max-request-timeout"`
	MaxResponseTimeout time.Duration `yaml:"max-response-timeout"`
	MaxIdleTimeout     time.Duration `yaml:"max-idle-timeout"`

	// true: the child keeps read-only disk access by jailing itself INTO the
	// web root, so files larger than max-cacheable-file-size are served from
	// disk. false: the child jails itself into an empty directory and loses
	// all disk access; only files cached at startup are served.
	ServeFilesNotInCache bool `yaml:"serve-files-not-in-cache"`

	// Files up to this size are cached in memory at startup.
	MaxCacheableFileSize int64 `yaml:"max-cacheable-file-size"`

	// Log the client address, method and URL of every request.
	LogRequests bool `yaml:"log-requests"`

	// Log file, written by the parent and rotated at 5 MB keeping 3 old
	// files ("" = log to stdout only). Must not be inside the web root.
	LogFile string `yaml:"log-file"`

	// Rotated-out log files older than this are deleted
	// ("0" = only the rotation count limits them).
	LogMaxAge time.Duration `yaml:"log-max-age"`

	// Derived at startup, not part of the YAML file:
	letsEncryptDomains []string        // web root subdirectories minus SelfSignedDomains
	allDomains         map[string]bool // punycoded whitelist of every servable domain
}

func defaultConfig() ServerConfig {
	return ServerConfig{
		WebRootDirectory:          "www_static",
		CertificateCacheDirectory: "certcache",
		HttpAddr:                  ":http",
		HttpsAddr:                 ":https",
		SelfSignedDomains:         []string{"localhost", "127.0.0.1"},
		ServerName:                "dma-srv",
		HttpHeaders: map[string]string{
			"X-Content-Type-Options":    "nosniff",
			"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
			"Content-Security-Policy":   "script-src 'self'",
			"X-Frame-Options":           "DENY",
			"Referrer-Policy":           "no-referrer",
			"Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
		},
		CertificateExpiryRefreshThreshold: 48 * time.Hour,
		MaxRequestTimeout:                 15 * time.Second,
		MaxResponseTimeout:                60 * time.Second,
		MaxIdleTimeout:                    60 * time.Second,
		ServeFilesNotInCache:              true,
		MaxCacheableFileSize:              1 << 20,
		LogRequests:                       true,
		LogFile:                           "server.log",
		LogMaxAge:                         30 * 24 * time.Hour,
	}
}

var config = defaultConfig()

// configFile is the resolved path of the loaded config file; the parent
// passes it to the child so both use the same one.
var configFile string

// loadConfig reads the YAML config file. Without an explicit path,
// config.yml next to the executable is used and created with the defaults
// when missing. Relative paths inside the config are resolved against the
// config file's directory, so the working directory never matters.
func loadConfig(path string) error {
	explicit := path != ""
	if !explicit {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		path = filepath.Join(filepath.Dir(exe), "config.yml")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	configFile = path

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := yaml.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
	case os.IsNotExist(err) && !explicit:
		log.Println("Creating default config file", path)
		out, _ := yaml.Marshal(config)
		if err := os.WriteFile(path, out, 0644); err != nil {
			return err
		}
	default:
		return err
	}

	base := filepath.Dir(path)
	config.WebRootDirectory = absJoin(base, config.WebRootDirectory)
	config.CertificateCacheDirectory = absJoin(base, config.CertificateCacheDirectory)
	if config.LogFile != "" {
		config.LogFile = absJoin(base, config.LogFile)
	}

	return checkConfig()
}

func absJoin(base, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(base, path)
}

// checkConfig validates and normalizes the configuration and derives the
// domain whitelists from the web root's subdirectories.
func checkConfig() error {
	for _, a := range []*string{&config.HttpAddr, &config.HttpsAddr} {
		addr, err := net.ResolveTCPAddr("tcp", *a)
		if err != nil {
			return fmt.Errorf("invalid listen address %q: %w", *a, err)
		}
		*a = addr.String()
	}

	if config.CertificateExpiryRefreshThreshold < time.Hour {
		log.Println("Warning: certificate-expiry-refresh-threshold raised to the minimum of one hour")
		config.CertificateExpiryRefreshThreshold = time.Hour
	}

	// The jailed child must never expose or overwrite these.
	for name, path := range map[string]string{
		"certificate-cache-directory": config.CertificateCacheDirectory,
		"log-file":                    config.LogFile,
	} {
		if path == "" {
			continue
		}
		if rel, err := filepath.Rel(config.WebRootDirectory, path); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
			return fmt.Errorf("%s (%s) must not be inside web-root-directory (%s)", name, path, config.WebRootDirectory)
		}
	}

	if err := os.MkdirAll(config.WebRootDirectory, 0755); err != nil {
		return err
	}

	// Every subdirectory of the web root is a served domain; the ones not
	// listed as self-signed get a Let's Encrypt certificate.
	selfSigned := make(map[string]bool, len(config.SelfSignedDomains))
	config.allDomains = make(map[string]bool)
	for _, d := range config.SelfSignedDomains {
		name, err := idna.Lookup.ToASCII(d)
		if err != nil {
			return fmt.Errorf("invalid self-signed domain %q: %w", d, err)
		}
		selfSigned[name] = true
		config.allDomains[name] = true
	}
	entries, err := os.ReadDir(config.WebRootDirectory)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name, err := idna.Lookup.ToASCII(e.Name())
		if err != nil {
			return fmt.Errorf("invalid domain directory %q: %w", e.Name(), err)
		}
		if !selfSigned[name] {
			config.letsEncryptDomains = append(config.letsEncryptDomains, name)
		}
		config.allDomains[name] = true
	}
	if len(config.allDomains) == 0 {
		return fmt.Errorf("no domains to serve: create one subdirectory per domain in %s", config.WebRootDirectory)
	}
	return nil
}
