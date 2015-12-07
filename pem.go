package ocspd

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

// ParsePEMCertificateBundle parses a PEM file containing the certificate chain
// (along with the private key, DH parameters, etc.) and return the first two
// certificates (the latter being expected to be for the issuer of the former).
func ParsePEMCertificateBundle(certBundleFileName string) (cert, issuer *x509.Certificate, err error) {
	data, err := ioutil.ReadFile(certBundleFileName)
	if err != nil {
		return
	}
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
	if cert == nil {
		return nil, nil, errors.New("No certificate found")
	}
	// If we're here, that means we found 'cert' but not 'issuer'
	// Try reading it from a ".issuer" file
	data, err = ioutil.ReadFile(certBundleFileName + ".issuer")
	if err != nil {
		return
	}
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
		if cert.CheckSignatureFrom(c) == nil {
			issuer = c
			return
		}
	}
	return cert, nil, errors.New("No issuer certificate found")
}
