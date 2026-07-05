package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/idna"
)

// rpcCache implements autocert.Cache against the parent process, which keeps
// the certificate directory outside the jail. Calls are strictly serialized:
// one request out on stdout, one response back in on stdin.
type rpcCache struct {
	mu  sync.Mutex
	enc *gob.Encoder
	dec *gob.Decoder
}

func (c *rpcCache) call(req cacheReq) (cacheResp, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var resp cacheResp
	if err := c.enc.Encode(&req); err != nil {
		return resp, err
	}
	if err := c.dec.Decode(&resp); err != nil {
		return resp, err
	}
	switch resp.Err {
	case "":
		return resp, nil
	case "miss":
		return resp, autocert.ErrCacheMiss
	default:
		return resp, errors.New(resp.Err)
	}
}

func (c *rpcCache) Get(_ context.Context, name string) ([]byte, error) {
	resp, err := c.call(cacheReq{Op: 'g', Name: name})
	return resp.Data, err
}

func (c *rpcCache) Put(_ context.Context, name string, data []byte) error {
	_, err := c.call(cacheReq{Op: 'p', Name: name, Data: data})
	return err
}

func (c *rpcCache) Delete(_ context.Context, name string) error {
	_, err := c.call(cacheReq{Op: 'd', Name: name})
	return err
}

// certManager returns Let's Encrypt certificates for the domains found in
// the web root (autocert does the issuing, renewing and in-memory caching)
// and memoized self-signed certificates for the self-signed domains — or as
// a fallback when Let's Encrypt fails.
type certManager struct {
	acme       *autocert.Manager
	selfSigned map[string]bool
	mu         sync.Mutex
	memo       map[string]*tls.Certificate // self-signed certificates by name
}

func newCertManager() *certManager {
	m := &certManager{
		acme: &autocert.Manager{
			Cache:       &rpcCache{enc: gob.NewEncoder(os.Stdout), dec: gob.NewDecoder(os.Stdin)},
			Prompt:      autocert.AcceptTOS,
			Email:       config.AcmeEmail,
			HostPolicy:  autocert.HostWhitelist(config.letsEncryptDomains...),
			RenewBefore: config.CertificateExpiryRefreshThreshold,
		},
		selfSigned: make(map[string]bool),
		memo:       make(map[string]*tls.Certificate),
	}
	for _, d := range config.SelfSignedDomains {
		if name, err := idna.Lookup.ToASCII(d); err == nil {
			m.selfSigned[name] = true
		}
	}
	return m
}

func (m *certManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	if name == "" {
		// No SNI (e.g. a request for https://127.0.0.1): try the local
		// address, which works when the IP is a whitelisted domain.
		if host, _, err := net.SplitHostPort(hello.Conn.LocalAddr().String()); err == nil {
			name = host
		}
	}
	name, err := idna.Lookup.ToASCII(name)
	if err != nil || !config.allDomains[name] {
		return nil, fmt.Errorf("certificate: no certificate for %q", hello.ServerName)
	}
	if !m.selfSigned[name] {
		cert, err := m.acme.GetCertificate(hello)
		if err == nil {
			return cert, nil
		}
		log.Printf("certificate: Let's Encrypt failed for %s (%v), using self-signed", name, err)
	}
	return m.selfSignedFor(name)
}

// selfSignedFor returns a memoized self-signed certificate for name,
// creating a fresh one when none exists or expiry comes close.
func (m *certManager) selfSignedFor(name string) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cert := m.memo[name]; cert != nil &&
		time.Until(cert.Leaf.NotAfter) > config.CertificateExpiryRefreshThreshold {
		return cert, nil
	}
	cert, err := makeSelfSigned(name)
	if err != nil {
		return nil, fmt.Errorf("certificate: self-signing %s: %w", name, err)
	}
	m.memo[name] = cert
	log.Println("certificate: created self-signed certificate for", name)
	return cert, nil
}

// makeSelfSigned creates a minimal ECDSA P-256 certificate for one domain
// name or IP address, with the SAN extension modern clients require.
func makeSelfSigned(name string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(config.CertificateExpiryRefreshThreshold + 14*24*time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// prewarm obtains or loads a certificate for every known domain so the first
// real request doesn't have to wait for ACME round trips.
func (m *certManager) prewarm() {
	for name := range config.allDomains {
		if _, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: name}); err != nil {
			log.Printf("certificate: prewarm %s: %v", name, err)
		}
	}
	log.Println("Certificates ready")
}
