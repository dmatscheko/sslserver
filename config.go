package main

import (
	"io/ioutil"
	"log"
	"time"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	// Let's Encrypt white list.
	// These domains are allowed to fetch a Let's Encrypt certificate.
	LetsEncryptDomains []string `yaml:"lets-encrypt-domains"`

	// Self signed certificates white list.
	// The domains for Let's Encrypt are automatically added to this list,
	// but you can include domains that are only allowed for self signed certificates.
	SelfSignedDomains []string `yaml:"self-signed-domains"`

	// Set to true if the program should exit when a certificate is about to expire.
	// This allows to cache the certificates to the hard disk after the next start.
	// Note 1: An external script has to restart the server!
	// Note 2: The server will only restart on Linux, because it makes no sense on Windows.
	TerminateOnCertificateExpiry bool `yaml:"terminate-on-certificate-expiry"`

	// Renew self signed certificates, if they expire within this duration.
	CertificateExpiryRefreshThreshold time.Duration `yaml:"certificate-expiry-refresh-threshold"`

	// Serve files if they are not cached in memory.
	ServeFilesNotInCache bool `yaml:"serve-files-not-in-cache"`

	// Maximum size for files that are cached in memory.
	// If files are not cached, and the server jails itself, it might be impossible to access the files.
	MaxCacheableFileSize int64 `yaml:"max-cacheable-file-size"`
}

// Set the default values of the config variables.
var config = ServerConfig{
	LetsEncryptDomains:                []string{"example.com"},
	SelfSignedDomains:                 []string{"localhost", "127.0.0.1"},
	TerminateOnCertificateExpiry:      false,
	CertificateExpiryRefreshThreshold: 48 * time.Hour,
	ServeFilesNotInCache:              false,
	MaxCacheableFileSize:              10 * 1024 * 1024,
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
	if config.CertificateExpiryRefreshThreshold < time.Hour {
		config.CertificateExpiryRefreshThreshold = time.Hour
		log.Println("Warning: duration-to-certificate-expiry-refresh is too low. Setting it to one hour.")
	}
}
