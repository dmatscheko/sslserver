package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

	// Transfer ownership of everything in the web root to root at startup
	// (applies when started as root). Only the owner of a file may chmod it,
	// so without this, content owned by the jail user could be made writable
	// again by the serving process.
	ChownWebRoot bool `yaml:"chown-web-root"`

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

	// Serve "www.example.com" from the "example.com" directory and vice
	// versa when the aliased name has no own directory.
	WwwAlias bool `yaml:"www-alias"`

	// How to answer requests for a host that is not served: "reject" (404;
	// unknown TLS names are always refused since certificates exist only
	// for the configured domains), "redirect-to-parent", "serve-parent" or
	// "serve-default". The parent modes fall back to the default site (the
	// reserved www_static/default directory) when no parent matches.
	UnknownDomains string `yaml:"unknown-domains"`

	// Dot files and directories are neither cached nor served, except the
	// names listed here (e.g. ".well-known").
	ServeDotNames []string `yaml:"serve-dot-names"`

	// Value of the "Server" response header ("" = no header).
	ServerName string `yaml:"server-name"`

	// Response headers. Entries here are merged over the built-in defaults;
	// set a value to "" to disable a default header.
	HttpHeaders map[string]string `yaml:"http-headers"`

	// Named groups of domains sharing setting overrides (see the
	// domains-override key in the generated config file).
	DomainsOverride map[string]DomainOverride `yaml:"domains-override"`

	// Renew or regenerate certificates that expire within this duration.
	CertificateExpiryRefreshThreshold time.Duration `yaml:"certificate-expiry-refresh-threshold"`

	MaxRequestTimeout  time.Duration `yaml:"max-request-timeout"`
	MaxResponseTimeout time.Duration `yaml:"max-response-timeout"`
	MaxIdleTimeout     time.Duration `yaml:"max-idle-timeout"`

	// Maximum number of concurrent connections per listener ("0" = unlimited).
	MaxConnections int `yaml:"max-connections"`

	// true: the child keeps read-only disk access by jailing itself INTO the
	// web root, so files larger than max-cacheable-file-size are served from
	// disk. false: the child jails itself into an empty directory and loses
	// all disk access; only files cached at startup are served.
	ServeFilesNotInCache bool `yaml:"serve-files-not-in-cache"`

	// Files up to this size are cached in memory at startup.
	MaxCacheableFileSize int64 `yaml:"max-cacheable-file-size"`

	// Stop caching once the total of cached bytes (including precompressed
	// variants) reaches this limit; further files are treated like files
	// above max-cacheable-file-size ("0" = unlimited).
	MaxTotalCacheSize int64 `yaml:"max-total-cache-size"`

	// Log the client address, method and URL of every request.
	LogRequests bool `yaml:"log-requests"`

	// Log file, written by the parent and rotated at 5 MB keeping 3 old
	// files ("" = log to stdout only). Must not be inside the web root.
	LogFile string `yaml:"log-file"`

	// Rotated-out log files older than this are deleted
	// ("0" = only the rotation count limits them).
	LogMaxAge time.Duration `yaml:"log-max-age"`

	// Derived at startup, not part of the YAML file:
	letsEncryptDomains []string                     // every servable host that uses Let's Encrypt
	domainDir          map[string]string            // servable host -> web root subdirectory
	selfSigned         map[string]bool              // hosts that get self-signed certificates
	dotNames           map[string]bool              // allowed dot names from ServeDotNames
	domainHeaders      map[string]map[string]string // directory domain -> effective headers
	serveHTTP          map[string]bool              // directory domains served over plain HTTP
	domainUnknown      map[string]string            // directory domain -> unknown-domains override
	defaultSite        bool                         // the reserved "default" directory exists
}

// DomainOverride is a named group of domains that share setting overrides
// (one entry of the domains-override config key).
type DomainOverride struct {
	// The served domains this group applies to. A www alias inherits the
	// overrides of the domain whose directory it serves.
	Domains []string `yaml:"domains"`

	// Headers merged over the global HttpHeaders for these domains.
	HttpHeaders map[string]string `yaml:"http-headers"`

	// Serve these domains over plain HTTP too, instead of redirecting HTTP
	// requests to HTTPS. HTTPS keeps working for them as well.
	ServeHttp bool `yaml:"serve-http"`

	// Override the global unknown-domains behavior for unknown subdomains
	// of these domains ("" = use the global setting).
	UnknownDomains string `yaml:"unknown-domains"`
}

func defaultConfig() ServerConfig {
	return ServerConfig{
		WebRootDirectory:          "www_static",
		ChownWebRoot:              true,
		CertificateCacheDirectory: "certcache",
		HttpAddr:                  ":http",
		HttpsAddr:                 ":https",
		SelfSignedDomains:         []string{"localhost", "127.0.0.1"},
		WwwAlias:                  false,
		UnknownDomains:            "reject",
		ServeDotNames:             []string{".well-known"},
		ServerName:                "dma-srv",
		HttpHeaders: map[string]string{
			"X-Content-Type-Options":    "nosniff",
			"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
			"Content-Security-Policy":   "script-src 'self'",
			"X-Frame-Options":           "DENY",
			"Referrer-Policy":           "no-referrer",
			"Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
		},
		DomainsOverride:                   map[string]DomainOverride{},
		CertificateExpiryRefreshThreshold: 48 * time.Hour,
		MaxRequestTimeout:                 15 * time.Second,
		MaxResponseTimeout:                60 * time.Second,
		MaxIdleTimeout:                    60 * time.Second,
		MaxConnections:                    1024,
		ServeFilesNotInCache:              true,
		MaxCacheableFileSize:              1 << 20,
		MaxTotalCacheSize:                 256 << 20,
		LogRequests:                       true,
		LogFile:                           "server.log",
		LogMaxAge:                         30 * 24 * time.Hour,
	}
}

var config = defaultConfig()

// defaultConfigFile is written on first start. Every value in it is the
// default; a test asserts that it stays in sync with defaultConfig().
const defaultConfigFile = `# sslserver configuration.
# Every value in this generated file is the default: keys you remove fall
# back to exactly these values, and the "Default:" comments let you restore
# single values after changing them. Unknown or misspelled keys are rejected
# at startup. Durations use Go syntax (15s, 48h). Relative paths are
# resolved against this file's directory.

# The web root: one subdirectory per domain, named exactly like the domain
# it serves (e.g. www_static/example.com). Created if missing. All contents
# are permanently made world-readable and read-only at startup.
# Default: www_static
web-root-directory: www_static

# Give everything in the web root to root at startup (applies when started
# as root). The owner of a file may always chmod it writable again, so
# read-only content must be owned by root to be truly immutable for the
# jailed serving user. Disable this if a non-root user deploys the content.
# Default: true
chown-web-root: true

# Let's Encrypt account key, private keys and certificates. Used by the
# parent process only; must be outside the web root.
# Default: certcache
certificate-cache-directory: certcache

# Contact e-mail for the Let's Encrypt account (expiry notices).
# Optional but recommended. Default: ""
acme-email: ""

# Listen addresses; service names are allowed. The HTTP server answers ACME
# challenges and redirects everything else to HTTPS (always port 443).
# Defaults: ":http" and ":https"
http-addr: :http
https-addr: :https

# Domains and IPs that never use Let's Encrypt and get a self-signed
# certificate instead. A web root directory of the same name is only needed
# if content should be served for them.
# Default: [localhost, 127.0.0.1]
self-signed-domains: [localhost, 127.0.0.1]

# Serve "www.example.com" from the "example.com" directory and vice versa
# when the aliased name has no own directory. Aliases use the same
# certificate type as the original; their certificates are obtained on
# first use. Default: false
www-alias: false

# How to answer requests for a host that is not served, e.g. an unknown
# subdomain. One of:
#   reject             404, and unknown TLS names are refused
#   redirect-to-parent redirect to the nearest parent domain that is served
#   serve-parent       serve the nearest parent domain's content
#   serve-default      serve the content of www_static/default
# The parent modes fall back to serve-default when no parent matches. The
# directory name "default" is reserved: it is not a domain and never gets a
# certificate. Certificates are ONLY ever obtained for the configured
# domains; with a mode other than reject, an unknown subdomain completes
# the TLS handshake with its parent domain's certificate (browsers show a
# name warning once) and any other unknown name with one shared self-signed
# placeholder certificate. Default: reject
unknown-domains: reject

# Dot files and directories are neither cached nor served, except the names
# listed here. Default: [.well-known]
serve-dot-names: [.well-known]

# Value of the "Server" response header ("" = no header).
# Default: dma-srv
server-name: dma-srv

# Response headers, merged over the built-in defaults shown here. Set a
# value to "" to drop a default header; add extra headers (for example
# Cache-Control) as new keys.
http-headers:
    Content-Security-Policy: script-src 'self'
    Permissions-Policy: geolocation=(), microphone=(), camera=()
    Referrer-Policy: no-referrer
    Strict-Transport-Security: max-age=63072000; includeSubDomains
    X-Content-Type-Options: nosniff
    X-Frame-Options: DENY

# Named override groups: each group applies its settings to all domains
# listed in it (a www alias inherits the overrides of the domain whose
# directory it serves; every domain may be covered by one group only).
# Per group:
#   domains:         the served domains the group applies to
#   http-headers:    headers merged over the global http-headers above
#   serve-http:      serve these domains over plain HTTP too, instead of
#                    redirecting HTTP to HTTPS (HTTPS keeps working)
#   unknown-domains: overrides the global unknown-domains setting for
#                    unknown subdomains of these domains
# Example:
#     domains-override:
#         production:
#             serve-http: false
#             unknown-domains: redirect-to-parent
#             http-headers:
#                 Content-Security-Policy: script-src 'self' 'unsafe-inline'
#             domains: [example.com, www.example.com]
#         playground:
#             serve-http: true
#             domains: [test.example.org]
# Default: {}
domains-override: {}

# Renew certificates this long before they expire (minimum 1h). Self-signed
# certificates are valid for this duration plus 14 days.
# Default: 48h
certificate-expiry-refresh-threshold: 48h

# Read, write and keep-alive timeouts of both servers.
# Defaults: 15s, 60s, 60s
max-request-timeout: 15s
max-response-timeout: 60s
max-idle-timeout: 60s

# Maximum number of concurrent connections per listener ("0" = unlimited).
# Default: 1024
max-connections: 1024

# true: the server jails itself INTO the web root, keeps read-only access,
# and serves files that are not cached (larger than max-cacheable-file-size
# or created after startup) from disk. false: the server jails itself into
# an empty directory and loses all disk access; only cached files can be
# served. Default: true
serve-files-not-in-cache: true

# Files up to this size (in bytes) are cached in memory at startup.
# Default: 1048576 (1 MiB)
max-cacheable-file-size: 1048576

# Stop caching once the total of cached bytes (including the precompressed
# variants) reaches this limit; further files are treated like files above
# max-cacheable-file-size ("0" = unlimited). Default: 268435456 (256 MiB)
max-total-cache-size: 268435456

# Log the client address, method, host and path of every request.
# Default: true
log-requests: true

# Log file, written by the parent process and rotated at 5 MB keeping 3 old
# files; must be outside the web root ("" = log to stdout only).
# Default: server.log
log-file: server.log

# Rotated-out log files older than this are deleted, checked hourly
# ("0" = only the rotation count limits them). Default: 720h (30 days)
log-max-age: 720h
`

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
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true) // reject unknown or misspelled keys
		if err := dec.Decode(&config); err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
	case os.IsNotExist(err) && !explicit:
		log.Println("Creating default config file", path)
		if err := os.WriteFile(path, []byte(defaultConfigFile), 0644); err != nil {
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

	// Dot files are hidden by default; validate the configured exceptions.
	config.dotNames = make(map[string]bool, len(config.ServeDotNames))
	for _, n := range config.ServeDotNames {
		if !strings.HasPrefix(n, ".") || n == "." || n == ".." || strings.ContainsAny(n, `/\`) {
			return fmt.Errorf("invalid serve-dot-names entry %q: must be a plain name starting with a dot", n)
		}
		config.dotNames[n] = true
	}

	// Every subdirectory of the web root is a served domain; the ones not
	// listed as self-signed get a Let's Encrypt certificate.
	config.selfSigned = make(map[string]bool, len(config.SelfSignedDomains))
	config.domainDir = make(map[string]string)
	for _, d := range config.SelfSignedDomains {
		name, err := idna.Lookup.ToASCII(d)
		if err != nil {
			return fmt.Errorf("invalid self-signed domain %q: %w", d, err)
		}
		config.selfSigned[name] = true
		config.domainDir[name] = name
	}
	entries, err := os.ReadDir(config.WebRootDirectory)
	if err != nil {
		return err
	}
	rootResolved, err := filepath.EvalSymlinks(config.WebRootDirectory)
	if err != nil {
		return err
	}
	for _, e := range entries {
		isSymlink := e.Type()&fs.ModeSymlink != 0
		if !e.IsDir() && !isSymlink {
			continue
		}
		if e.Name() == "default" {
			// Reserved: the fallback site for unknown-domains. It is not a
			// domain and MUST never appear in any certificate whitelist.
			config.defaultSite = e.IsDir()
			continue
		}
		name, err := idna.Lookup.ToASCII(e.Name())
		if err != nil {
			return fmt.Errorf("invalid domain directory %q: %w", e.Name(), err)
		}
		if name != e.Name() {
			// Cache keys and disk paths use the directory name as-is, but
			// requests arrive in the lowercase ASCII (punycode) form.
			log.Printf("Warning: domain directory %q should be named %q to be servable", e.Name(), name)
		}
		if !isSymlink {
			config.domainDir[name] = name
			continue
		}
		// A symlinked domain directory (www.example.com -> example.com) is
		// served as an alias of its target, which must be a sibling
		// directory inside the web root.
		target, err := filepath.EvalSymlinks(filepath.Join(config.WebRootDirectory, e.Name()))
		if err != nil {
			log.Printf("Warning: ignoring domain symlink %q: %v", e.Name(), err)
			continue
		}
		if info, err := os.Stat(target); err != nil || !info.IsDir() || filepath.Dir(target) != rootResolved {
			log.Printf("Warning: ignoring domain symlink %q: target %q is not a sibling directory inside the web root", e.Name(), target)
			continue
		}
		targetName, err := idna.Lookup.ToASCII(filepath.Base(target))
		if err != nil {
			log.Printf("Warning: ignoring domain symlink %q: %v", e.Name(), err)
			continue
		}
		config.domainDir[name] = targetName
		if config.selfSigned[targetName] {
			config.selfSigned[name] = true
		}
	}

	// Serve "www.x" from the "x" directory and vice versa. A dedicated
	// directory always wins; aliases inherit the original's certificate type.
	if config.WwwAlias {
		hosts := make([]string, 0, len(config.domainDir))
		for h := range config.domainDir {
			hosts = append(hosts, h)
		}
		for _, h := range hosts {
			alias := wwwAlias(h)
			if _, exists := config.domainDir[alias]; alias == "" || exists {
				continue
			}
			config.domainDir[alias] = config.domainDir[h]
			if config.selfSigned[h] {
				config.selfSigned[alias] = true
			}
		}
	}

	for host := range config.domainDir {
		if !config.selfSigned[host] {
			config.letsEncryptDomains = append(config.letsEncryptDomains, host)
		}
	}
	if len(config.domainDir) == 0 {
		return fmt.Errorf("no domains to serve: create one subdirectory per domain in %s", config.WebRootDirectory)
	}

	switch config.UnknownDomains {
	case "reject", "redirect-to-parent", "serve-parent", "serve-default":
	default:
		return fmt.Errorf("invalid unknown-domains value %q (reject, redirect-to-parent, serve-parent or serve-default)", config.UnknownDomains)
	}
	if config.UnknownDomains == "serve-default" && !config.defaultSite {
		return fmt.Errorf("unknown-domains is serve-default, but there is no %s directory", filepath.Join(config.WebRootDirectory, "default"))
	}

	// Validate and precompute the override groups. A listed name may be a
	// domain or one of its aliases; the overrides apply to the directory
	// domain, so aliases inherit them. Every directory may be covered by
	// at most one group.
	config.domainHeaders = map[string]map[string]string{}
	config.serveHTTP = map[string]bool{}
	config.domainUnknown = map[string]string{}
	appliedBy := map[string]string{} // directory domain -> group name
	for group, o := range config.DomainsOverride {
		switch o.UnknownDomains {
		case "", "reject", "redirect-to-parent", "serve-parent", "serve-default":
		default:
			return fmt.Errorf("domains-override %q: invalid unknown-domains value %q", group, o.UnknownDomains)
		}
		if o.UnknownDomains == "serve-default" && !config.defaultSite {
			return fmt.Errorf("domains-override %q: unknown-domains is serve-default, but there is no %s directory", group, filepath.Join(config.WebRootDirectory, "default"))
		}
		for _, d := range o.Domains {
			name, err := idna.Lookup.ToASCII(d)
			if err != nil {
				return fmt.Errorf("domains-override %q: invalid domain %q: %w", group, d, err)
			}
			dir, ok := config.domainDir[name]
			if !ok {
				return fmt.Errorf("domains-override %q: %q does not match any served domain", group, d)
			}
			if prev, ok := appliedBy[dir]; ok {
				if prev != group {
					return fmt.Errorf("domain %q is covered by both override groups %q and %q", dir, prev, group)
				}
				continue // an alias and its domain in the same group
			}
			appliedBy[dir] = group
			if o.ServeHttp {
				config.serveHTTP[dir] = true
			}
			if o.UnknownDomains != "" {
				config.domainUnknown[dir] = o.UnknownDomains
			}
			if len(o.HttpHeaders) > 0 {
				merged := make(map[string]string, len(config.HttpHeaders)+len(o.HttpHeaders))
				for k, v := range config.HttpHeaders {
					merged[k] = v
				}
				for k, v := range o.HttpHeaders {
					merged[k] = v
				}
				config.domainHeaders[dir] = merged
			}
		}
	}
	return nil
}

// wwwAlias returns the "www."-toggled form of a host name, or "" when no
// alias makes sense (IP addresses).
func wwwAlias(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	if after, found := strings.CutPrefix(host, "www."); found {
		return after
	}
	return "www." + host
}
