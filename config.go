package main

import "time"

// Let's Encrypt white list.
// Those domains are allowed to fetch a Let's Encrypt certificate.
var domainsLetsEncrypt []string = []string{"example.com"}

// Self signed certificates white list.
// The domains for Let's Encrypt are automatically added to this list,
// but you can include domains that are only allowd for self signed certificates.
var domainsSelfSigned []string = []string{"localhost", "127.0.0.1"}

// Set to true if the program should exit when a certificate is about to expire.
// This allows to cache the certificates to the hard disk after the next start.
// An external script has to restart the server.
var terminateIfCertificateExpires bool = false

// Renew self signed certificates, if they expire within this duration.
var durationToCertificateExpiryRefresh time.Duration = 24 * time.Hour
