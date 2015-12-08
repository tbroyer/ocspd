package ocspd

import (
	"bytes"
	"crypto/x509"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

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

// NeedsRefresh determines where the given OCSP response needs to be refreshed.
// If the response has no NextUpdate information, it needs to be refreshed.
// Otherwise, it'll need to be refreshed halfway through its validity period,
// and to avoid refreshing too many times during that interval the last refresh
// time and the checks period are used as guidance.
func NeedsRefresh(resp *ocsp.Response, mtime time.Time, period time.Duration) bool {
	// TODO: take into account the signer certificate's NotAfter and NotBefore
	now := time.Now()
	if resp.NextUpdate.IsZero() || resp.NextUpdate.Before(now) {
		return true
	}
	if now.Add(period).After(resp.NextUpdate) {
		// next time we'll check the response will be expired
		return true
	}
	h := resp.ThisUpdate.Add(resp.NextUpdate.Sub(resp.ThisUpdate) / 2)
	if h.After(now) {
		// still in the first half of the validity period
		return false
	}
	if h.After(mtime) {
		// this is the first time we check during the second half of the validity period
		return true
	}
	// TODO: refresh more often during the second half of the validity period
	return false
}

// NeedsRefreshFile applies NeedsRefresh heuristics to an OCSP response stored
// in a file: it will check if the file exists, parse it, then call NeedsRefresh
// with parsed OCSP response, the file's last modification time and the given period.
func NeedsRefreshFile(filename string, issuer *x509.Certificate, period time.Duration) (bool, error) {
	stats, err := os.Stat(filename)
	if err != nil {
		return true, err
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return true, err
	}
	resp, err := ocsp.ParseResponse(data, issuer)
	if err != nil {
		return true, err
	}
	// TODO: make check period configurable
	return NeedsRefresh(resp, stats.ModTime(), period), nil
}
