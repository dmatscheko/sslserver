package main

import (
	"io/ioutil"
	"log"
	"time"

	"gopkg.in/yaml.v3"
)

// Let's Encrypt white list.
// Those domains are allowed to fetch a Let's Encrypt certificate.
var domainsLetsEncrypt []string = []string{"example.com"}

// Self signed certificates white list.
// The domains for Let's Encrypt are automatically added to this list,
// but you can include domains that are only allowd for self signed certificates.
var domainsSelfSigned []string = []string{"localhost", "127.0.0.1"}

// Set to true if the program should exit when a certificate is about to expire.
// This allows to cache the certificates to the hard disk after the next start.
// Note 1: An external script has to restart the server!
// Note 2: The server will only restart on Linux, because it makes no sense on Windows.
var terminateIfCertificateExpires bool = false

// Renew self signed certificates, if they expire within this duration.
var durationToCertificateExpiryRefresh time.Duration = 12 * time.Hour

// Serve files if they are not cached in memory.
var serveNonCachedFiles bool = false

// Maximum size for files that are cached in memory.
// If files are not cached, and the server jails itself, it might be impossible to access the files.
var cacheFileSizeLimit int64 = 10 * 1024 * 1024

type Config struct {
	DomainsLetsEncrypt                 []string      `yaml:"domains-lets-encrypt"`
	DomainsSelfSigned                  []string      `yaml:"domains-self-signed"`
	TerminateIfCertificateExpires      bool          `yaml:"terminate-if-certificate-expires"`
	DurationToCertificateExpiryRefresh time.Duration `yaml:"duration-to-certificate-expiry-refresh"`
	ServeNonCachedFiles                bool          `yaml:"serve-non-cached-files"`
	CacheFileSizeLimit                 int64         `yaml:"cache-file-size-limit"`
}

func readConfig() {
	// Read the config file.
	data, err := ioutil.ReadFile("config.yml")
	if err != nil {
		log.Println("Configuration file config.yaml does not exist. Creating the file...")

		// If the file does not exist, create it.
		var config Config
		config.DomainsLetsEncrypt = domainsLetsEncrypt
		config.DomainsSelfSigned = domainsSelfSigned
		config.TerminateIfCertificateExpires = terminateIfCertificateExpires
		config.DurationToCertificateExpiryRefresh = durationToCertificateExpiryRefresh
		config.ServeNonCachedFiles = serveNonCachedFiles
		config.CacheFileSizeLimit = cacheFileSizeLimit

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
	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Println("config.yaml seems to have invalid syntax or entries.")
		return
	}

	// Set the values of the variables from the config struct.
	domainsLetsEncrypt = config.DomainsLetsEncrypt
	domainsSelfSigned = config.DomainsSelfSigned
	terminateIfCertificateExpires = config.TerminateIfCertificateExpires
	durationToCertificateExpiryRefresh = config.DurationToCertificateExpiryRefresh
	serveNonCachedFiles = config.ServeNonCachedFiles
	cacheFileSizeLimit = config.CacheFileSizeLimit
}
