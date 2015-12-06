package ocspd

import (
	"bytes"
	"crypto/x509"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/ocsp"
)

// Update queries the OCSP responder and returns an OCSP response
// If responderURL is empty then the OCSP responder URL is extracted from the
// passed in certificates.
func Update(cert, issuer *x509.Certificate, responderURL string) ([]byte, error) {
	var err error
	if len(responderURL) == 0 {
		responderURL, err = ResponderURL(cert)
		if err != nil {
			responderURL, err = ResponderURL(issuer)
			if err != nil {
				return nil, err
			}
		}
	}
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, err
	}
	// TODO: conditionally use http.Get() if len(bytes)<255 as hinted in RFC
	// TODO: observe HTTP cache semantics
	resp, err := http.Post(responderURL, "application/ocsp-request", bytes.NewBuffer(req))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Bad HTTP status")
	}
	if !strings.EqualFold(resp.Header.Get("Content-Type"), "application/ocsp-response") {
		return nil, errors.New("Bad response content-type")
	}
	var bodyReader io.Reader = resp.Body
	if resp.ContentLength >= 0 {
		bodyReader = io.LimitReader(bodyReader, resp.ContentLength)
	} // TODO: else, set a limit
	return ioutil.ReadAll(bodyReader)
}

// ResponderURL extracts the OCSP responder URL from the given certificate.
func ResponderURL(cert *x509.Certificate) (string, error) {
	for _, ocspServer := range cert.OCSPServer {
		if !strings.EqualFold(ocspServer[0:7], "http://") && !strings.EqualFold(ocspServer[0:8], "https://") {
			continue
		}
		if _, err := url.Parse(ocspServer); err != nil {
			return "", err
		}
		return ocspServer, nil
	}
	return "", errors.New("Cannot find an OCSP URL")
}
