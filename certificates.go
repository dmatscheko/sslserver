package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/idna"
)

// The white list of domains for self signed certificates.
var allowedDomainsSelfSignedWhiteList map[string]bool = nil

// certCache holds the cached self signed TLS certificates.
var certCache map[string]*tls.Certificate = nil

// Create a new autocert manager.
var m = &autocert.Manager{
	Cache:       autocert.DirCache("certcache"),
	Prompt:      autocert.AcceptTOS,
	HostPolicy:  autocert.HostWhitelist(config.LetsEncryptDomains...),
	RenewBefore: config.CertificateExpiryRefreshThreshold + 24*time.Hour, // This way, RenewBefore is always longer than the certificate expiry timeout when the server terminates.
}

// initCertificates initializes the white list of domains for self signed certificates and also the cache for the self signed certificates.
func initCertificates() time.Duration {
	// Add the domains for Let's Encrypt to the domains for which self signed certificates can be created.
	config.SelfSignedDomains = append(config.SelfSignedDomains, config.LetsEncryptDomains...)

	// Initialize the white list of domains for self signed certificates.
	allowedDomainsSelfSignedWhiteList = make(map[string]bool, len(config.SelfSignedDomains))
	for _, h := range config.SelfSignedDomains {
		if h, err := idna.Lookup.ToASCII(h); err == nil {
			allowedDomainsSelfSignedWhiteList[h] = true
		}
	}

	// Initialize the cache for the self signed certificates.
	certCache = make(map[string]*tls.Certificate, len(allowedDomainsSelfSignedWhiteList))

	// Initialize certificates before going to jail.
	var shortestDuration time.Duration = 10 * 365 * 24 * time.Hour // Initial duration is 10 years which should be longer than any certificate expiration.
	log.Println("Checking certificates...")
	for _, serverName := range config.SelfSignedDomains {
		cert, err := getCertificate(&tls.ClientHelloInfo{ServerName: serverName})
		if err != nil {
			log.Println("Error when initializing certificate for:", serverName, "\nError:", err)
			continue
		}

		// Parse the certificate from a PEM-encoded byte slice.
		if cert.Leaf == nil {
			parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				log.Fatal(err)
			}
			cert.Leaf = parsedCert
		}

		// Set the cache.
		certCache[serverName] = cert

		// Get the expiration time of the SSL certificate.
		expiration := cert.Leaf.NotAfter
		// Convert it into the duration from now.
		duration := time.Until(expiration)
		// Substract the durationToCertificateExpiryRefresh.
		duration = duration - config.CertificateExpiryRefreshThreshold

		if shortestDuration > duration {
			shortestDuration = duration
		}
	}

	return shortestDuration
}

// getTLSCert creates a self-signed TLS certificate.
func getTLSCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	if name == "" {
		return nil, errors.New("self signed cert: missing server name")
	}

	// Note that this conversion is necessary because some server names in the handshakes
	// started by some clients (such as cURL) are not converted to Punycode, which will
	// prevent us from obtaining certificates for them. In addition, we should also treat
	// example.com and EXAMPLE.COM as equivalent and return the same certificate for them.
	// Fortunately, this conversion also helped us deal with this kind of mixedcase problems.
	//
	// Due to the "σςΣ" problem (see https://unicode.org/faq/idn.html#22), we can't use
	// idna.Punycode.ToASCII (or just idna.ToASCII) here.
	name, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return nil, errors.New("self signed cert: server name contains invalid character")
	}

	// Check if the domain name is in the white list.
	if !allowedDomainsSelfSignedWhiteList[name] {
		return nil, errors.New("self signed cert: server name not in white list: " + name)
	}

	// Generate a new private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return &tls.Certificate{}, err
	}

	// Create a template for the certificate.
	template := x509.Certificate{
		SerialNumber: big.NewInt(412294),
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"Acme Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(config.CertificateExpiryRefreshThreshold + 14*24*time.Hour), // valid for two weeks plus durationToCertificateExpiryRefresh.
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create the certificate.
	publicKey := &privateKey.PublicKey
	certificate, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return &tls.Certificate{}, err
	}

	// Encode the private key and certificate in PEM format.
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})

	// Create a TLS certificate using the PEM-encoded bytes.
	cert, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return &tls.Certificate{}, err
	}

	return &cert, nil
}

// getCertificate tries to fetch a certificate from Let's Encrypt and, if that fails,
// creates a self-signed certificate.
func getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Return the self signed certificate if it was created before.
	// Only try to switch back to Let's Encrypt, after the self signed certificate expires.

	// Get domain name.
	name := hello.ServerName
	if name == "" {
		return nil, errors.New("self signed cert: missing server name")
	}
	// Note that this conversion is necessary because some server names in the handshakes
	// started by some clients (such as cURL) are not converted to Punycode, which will
	// prevent us from obtaining certificates for them. In addition, we should also treat
	// example.com and EXAMPLE.COM as equivalent and return the same certificate for them.
	// Fortunately, this conversion also helped us deal with this kind of mixedcase problems.
	//
	// Due to the "σςΣ" problem (see https://unicode.org/faq/idn.html#22), we can't use
	// idna.Punycode.ToASCII (or just idna.ToASCII) here.
	name, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return nil, errors.New("self signed cert: server name contains invalid character")
	}
	if certCache[name] != nil {
		// Parse the certificate from a PEM-encoded byte slice.
		if certCache[name].Leaf == nil {
			parsedCert, err := x509.ParseCertificate(certCache[name].Certificate[0])
			if err != nil {
				return nil, err
			}
			certCache[name].Leaf = parsedCert
		}

		// Get the expiration time of the SSL certificate.
		expiration := certCache[name].Leaf.NotAfter
		// Convert it into the duration from now.
		duration := time.Until(expiration)
		// Check if expired with durationBeforeCertificateExpiryRefresh time buffer.
		if duration < config.CertificateExpiryRefreshThreshold {
			// Clear certCache[name] from the expired certificate, so that it can be checked faster.
			certCache[name] = nil
			log.Printf("Self signed certificate expires within a duration of %s.\n", config.CertificateExpiryRefreshThreshold)
		} else {
			// Certificate is valid with durationBeforeCertificateExpiryRefresh time buffer.
			return certCache[name], nil
		}
	}

	// Try to fetch a certificate from Let's Encrypt.
	cert, err := m.GetCertificate(hello)
	if err == nil {
		log.Println("  Got Let's Encrypt certificate for:", name)
		// Return the certificate if successful.
		return cert, nil
	}

	// If autocert returned any error, create a self-signed certificate.
	cert, err = getTLSCert(hello)
	if err == nil {
		log.Println("  Created self signed certificate for:", name)
		certCache[name] = cert
		return cert, nil
	}
	return nil, err
}
