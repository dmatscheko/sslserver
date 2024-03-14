package main

import (
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	// The base directory (the web root) to serve static files from.
	// Warning, the permissions for all files will be set to `a=r`, and for all directories to `a=rx`.
	// This is also the directory in which to jail the process on Linux.
	WebRootDirectory string `yaml:"web-root-directory"`

	// Let's Encrypt certificates are stored in this directory.
	CertificateCacheDirectory string `yaml:"certificate-cache-directory"`

	// The HTTP address to bind the server to.
	HttpAddr string `yaml:"http-addr"`

	// The HTTPS address to bind the server to.
	HttpsAddr string `yaml:"https-addr"`

	// Let's Encrypt white list.
	// These domains are allowed to fetch a Let's Encrypt certificate.
	// This is not directly configurable. Instead, the domain directories in www_static will be used
	// to populate this, and then SelfSignedDomains will be substracted.
	letsEncryptDomains []string

	// Self signed certificates white list.
	// For this domains, no certificate will be fetched from Let's Encrypt.
	SelfSignedDomains []string `yaml:"self-signed-domains"`

	// All allowed domains. This are LetsEncryptDomains + SelfSignedDomains.
	allDomains []string

	// Name of the web server used as Server header.
	ServerName string `yaml:"server-name"`

	// Security http headers.
	HttpHeaderXContentTypeOptions     string `yaml:"http-header-x-content-type-options"`
	HttpHeaderStrictTransportSecurity string `yaml:"http-header-strict-transport-security"`
	HttpHeaderContentSecurityPolicy   string `yaml:"http-header-content-security-policy"`
	HttpHeaderXFrameOptions           string `yaml:"http-header-x-frame-options"`

	// Renew certificates, if they expire within this duration.
	CertificateExpiryRefreshThreshold time.Duration `yaml:"certificate-expiry-refresh-threshold"`

	// Maximum duration to wait for a request to complete.
	MaxRequestTimeout time.Duration `yaml:"max-request-timeout"`

	// Maximum duration to wait for a response to complete.
	MaxResponseTimeout time.Duration `yaml:"max-response-timeout"`

	// Maximum duration to wait for a follow up request.
	MaxIdleTimeout time.Duration `yaml:"max-idle-timeout"`

	// Serve files if they are not cached in memory. If this is `false`, the server will not even try to read newer files into the cache.
	ServeFilesNotInCache bool `yaml:"serve-files-not-in-cache"`

	// Maximum size for files that are cached in memory.
	MaxCacheableFileSize int64 `yaml:"max-cacheable-file-size"`

	// Log the client IP and URL path of each request.
	LogRequests bool `yaml:"log-requests"`

	// The name of the log file. If the name is empty, the log output will only be written to stdout.
	LogFile string `yaml:"log-file"`

	/*
		TODO: Maybe:

		The HTTPS port where to redirect HTTP connections to, because there can be a proxy in front
		The maximum number of connections the server should allow at once
		The maximum request body size the server should allow
		The server's TLS/SSL certificate and key files
		The level of access logging to enable
		The location of the server's access and error logs
		The type of error handling to use (e.g. detailed errors or friendly error pages)
	*/

}

// Set the default values of the config variables.
var config = ServerConfig{
	WebRootDirectory:                  "www_static",
	CertificateCacheDirectory:         "certcache",
	HttpAddr:                          ":http",
	HttpsAddr:                         ":https",
	letsEncryptDomains:                []string{},
	SelfSignedDomains:                 []string{"localhost", "127.0.0.1"},
	allDomains:                        []string{},
	ServerName:                        "dma-srv",
	HttpHeaderXContentTypeOptions:     "nosniff",
	HttpHeaderStrictTransportSecurity: "max-age=63072000; includeSubDomains",
	HttpHeaderContentSecurityPolicy:   "script-src 'self'",
	HttpHeaderXFrameOptions:           "DENY",
	CertificateExpiryRefreshThreshold: 48 * time.Hour,
	MaxRequestTimeout:                 15 * time.Second,
	MaxResponseTimeout:                60 * time.Second,
	MaxIdleTimeout:                    60 * time.Second,
	ServeFilesNotInCache:              true,
	MaxCacheableFileSize:              1024 * 1024,
	LogRequests:                       true,
	LogFile:                           "server.log",
}

func readConfig() {
	// Read the config file.
	data, err := ioutil.ReadFile("config.yml")
	if err != nil {
		// If the file does not exist, create it.
		log.Println("Configuration file config.yaml does not exist. Creating the file...")

		data, err := yaml.Marshal(config)
		if err != nil {
			log.Println("Could not marshal config yaml.")
			return
		}

		err = ioutil.WriteFile("config.yml", data, 0644)
		if err != nil {
			log.Println("Could not write config yaml.")
			return
		}

		log.Println("Done.")
	}

	// Unmarshal the config data into a Config struct.
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Println("config.yaml seems to have invalid syntax or entries.")
		return
	}

	// Sanity checks.
	sanityChecks()
}

func printConfig(config ServerConfig) {
	log.Println("Config:")

	// Get the type of the config variable.
	t := reflect.TypeOf(config)

	// Iterate over all the fields of the config variable.
	for i := 0; i < t.NumField(); i++ {
		// Get the config entries name field and its yaml tag.
		nameField := t.Field(i)
		yamlTag := nameField.Tag.Get("yaml")

		// Get the config entries value field.
		valueField := reflect.ValueOf(config).Field(i)

		if valueField.CanInterface() && yamlTag != "" {
			// Print the field name and its value.
			log.Println("  "+yamlTag+":", valueField.Interface())
		}
	}
}

func sanityChecks() {
	// Ensure that the HttpAddr parameter is a valid address and convert its service name into the numeric port number.
	// If it is not valid, set it to ":80".
	addr, err := net.ResolveTCPAddr("tcp", config.HttpAddr)
	if err != nil {
		config.HttpAddr = ":80"
		log.Println("Warning: http-addr is invalid. Setting it to :80.")
	} else {
		config.HttpAddr = addr.String()
	}

	// Ensure that the HttpsAddr parameter is a valid address and convert its service name into the numeric port number.
	// If it is not valid, set it to ":443".
	addr, err = net.ResolveTCPAddr("tcp", config.HttpsAddr)
	if err != nil {
		config.HttpsAddr = ":443"
		log.Println("Warning: https-addr is invalid. Setting it to :443.")
	} else {
		config.HttpsAddr = addr.String()
	}

	// Ensure that the CertificateExpiryRefreshThreshold parameter has a minimum value of one hour.
	if config.CertificateExpiryRefreshThreshold < time.Hour {
		config.CertificateExpiryRefreshThreshold = time.Hour
		log.Println("Warning: certificate-expiry-refresh-threshold is too low. Setting it to one hour.")
	}

	// Verify that the LogFile parameter is a valid file path to an existing file.
	// If it is not valid, set it to an empty string to disable file logging.
	config.LogFile = filepath.Clean(config.LogFile)
	if fileInfo, _ := os.Stat(config.LogFile); fileInfo != nil && fileInfo.Mode().IsDir() {
		config.LogFile = ""
	}

	// Verify that the WebRootDirectory parameter is a valid path to an existing directory.
	// Create the directory if it does not exist.
	// If it is not valid, set it to "www_static".
	config.WebRootDirectory = filepath.Clean(config.WebRootDirectory)
	if fileInfo, _ := os.Stat(config.WebRootDirectory); fileInfo != nil && !fileInfo.Mode().IsDir() {
		config.WebRootDirectory = "www_static"
	}
	if _, err := os.Stat(config.WebRootDirectory); os.IsNotExist(err) {
		if err := os.MkdirAll(config.WebRootDirectory, 0555); err != nil {
			log.Fatal(err)
		}
	}

	// Verify that the CertificateCacheDirectory parameter is a valid path to an existing directory.
	// Create the directory if it does not exist.
	// If it is not valid, set it to "certcache".
	config.CertificateCacheDirectory = filepath.Clean(config.CertificateCacheDirectory)
	if fileInfo, _ := os.Stat(config.CertificateCacheDirectory); fileInfo != nil && !fileInfo.Mode().IsDir() {
		// The server has to be able to write certificates into this directory.
		// It should not be inside the jail or it will be set to read only.
		config.CertificateCacheDirectory = "certcache"
	}
	if _, err := os.Stat(config.CertificateCacheDirectory); os.IsNotExist(err) {
		if err := os.MkdirAll(config.CertificateCacheDirectory, 0700); err != nil {
			log.Fatal(err)
		}
	}

	// Fill the directory white list for which to create Let's Encrypt certificates
	config.letsEncryptDomains = getAllowedDomainsFromSubdirectories(config.WebRootDirectory, config.SelfSignedDomains)
	if len(config.letsEncryptDomains) == 0 && len(config.SelfSignedDomains) == 0 {
		log.Fatal("Error: No domain directories specified in web root")
	}

	// Set all allowed domains
	config.allDomains = append(config.letsEncryptDomains, config.SelfSignedDomains...)
}

// getAllowedDomainsFromSubdirectories retrieves allowed domains from subdirectories in the webroot directory.
func getAllowedDomainsFromSubdirectories(webrootDir string, selfSignedDomains []string) []string {
	var domains []string

	files, err := os.ReadDir(webrootDir)
	if err != nil {
		log.Println("Error reading directory:", err)
		return domains
	}

	for _, file := range files {
		resolvedFile, err := os.Stat(filepath.FromSlash(webrootDir + "/" + file.Name()))
		if err != nil {
			log.Println("Error reading directory:", err)
			return domains
		}

		if resolvedFile.IsDir() {
			domain := file.Name()
			for _, selfSignedDomain := range selfSignedDomains {
				if domain == selfSignedDomain {
					continue
				}
			}
			domains = append(domains, domain)
		}
	}

	return domains
}
