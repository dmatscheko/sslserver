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
	WebRootDirectory string `yaml:"web-root-directory"`

	// The HTTP address to bind the server to.
	HttpAddr string `yaml:"http-addr"`

	// The HTTPS address to bind the server to.
	HttpsAddr string `yaml:"https-addr"`

	// Let's Encrypt white list.
	// These domains are allowed to fetch a Let's Encrypt certificate.
	LetsEncryptDomains []string `yaml:"lets-encrypt-domains"`

	// Self signed certificates white list.
	// The domains for Let's Encrypt are automatically added to this list,
	// but you can include domains that are only allowed for self signed certificates.
	SelfSignedDomains []string `yaml:"self-signed-domains"`

	// Let's Encrypt certificates are stored in this directory.
	CertificateCacheDirectory string `yaml:"certificate-cache-directory"`

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
	// If files are not cached, and the server jails itself, it might be impossible to access the files.
	MaxCacheableFileSize int64 `yaml:"max-cacheable-file-size"`

	// Whether to jail the process or not.
	// If you jail the process, no file can exceed MaxCacheableFileSize.
	JailProcess bool `yaml:"jail-process"`

	// The directory in which to jail the process. Warning, the permissions for all files will be set to `a=r`, and for all directories to `a=rx`.
	JailDirectory string `yaml:"jail-directory"`

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
	WebRootDirectory:                  "jail/www_static",
	HttpAddr:                          ":http",
	HttpsAddr:                         ":https",
	LetsEncryptDomains:                []string{"example.com"},
	SelfSignedDomains:                 []string{"localhost", "127.0.0.1"},
	CertificateCacheDirectory:         "certcache",
	CertificateExpiryRefreshThreshold: 48 * time.Hour,
	MaxRequestTimeout:                 15 * time.Second,
	MaxResponseTimeout:                60 * time.Second,
	MaxIdleTimeout:                    60 * time.Second,
	ServeFilesNotInCache:              true,
	MaxCacheableFileSize:              1024 * 1024,
	JailProcess:                       true,
	JailDirectory:                     "jail",
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
		// Get the field and its yaml tag.
		field := t.Field(i)
		yamlTag := field.Tag.Get("yaml")

		// Print the field name and its value.
		log.Println("  "+yamlTag+":", reflect.ValueOf(config).Field(i).Interface())
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
	// If it is not valid, set it to "jail/www_static".
	config.WebRootDirectory = filepath.Clean(config.WebRootDirectory)
	if fileInfo, _ := os.Stat(config.WebRootDirectory); fileInfo != nil && !fileInfo.Mode().IsDir() {
		config.WebRootDirectory = "jail/www_static"
	}
	if _, err := os.Stat(config.WebRootDirectory); os.IsNotExist(err) {
		if err := os.MkdirAll(config.WebRootDirectory, 0555); err != nil {
			log.Fatal(err)
		}
	}

	// Verify that the JailDirectory parameter is a valid path to an existing directory.
	// Create the directory if it does not exist.
	// If it is not valid, set it to "jail".
	config.JailDirectory = filepath.Clean(config.JailDirectory)
	if fileInfo, _ := os.Stat(config.JailDirectory); fileInfo != nil && !fileInfo.Mode().IsDir() {
		config.JailDirectory = "jail"
	}
	if _, err := os.Stat(config.JailDirectory); os.IsNotExist(err) {
		if err := os.MkdirAll(config.JailDirectory, 0555); err != nil {
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
}
