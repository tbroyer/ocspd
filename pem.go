package ocspd

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// ParsePEMCertificateBundle parses a PEM file containing the certificate chain
// (along with the private key, DH parameters, etc.) and return the first two
// certificates (the latter being expected to be for the issuer of the former).
func ParsePEMCertificateBundle(data []byte) (cert, issuer *x509.Certificate, err error) {
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		var c *x509.Certificate
		c, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return
		}
		if cert == nil {
			cert = c
		} else if cert.CheckSignatureFrom(c) == nil {
			issuer = c
			return
		}
	}
	return nil, nil, errors.New("No certificate found")
}
