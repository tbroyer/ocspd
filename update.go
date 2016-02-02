package ocspd

import (
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Update queries the OCSP responder and returns an OCSP response.
//
// If responderURL is empty then the OCSP responder URL is extracted from the
// passed in certificates.
func Update(cert, issuer *x509.Certificate, responderURL string) ([]byte, error) {
	r, err := FetchForCert(cert, issuer, responderURL, "", time.Time{}, time.Time{})
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, nil
	}
	return r.RawOCSPResponse, nil
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

// NeedsRefresh determines whether the given OCSP response needs to be refreshed.
//
// If the response has no NextUpdate information, it needs to be refreshed.
// Otherwise, it'll need to be refreshed halfway through its validity period,
// and to avoid refreshing too many times during that interval the last refresh
// time and the checks period are used as guidance.
func NeedsRefresh(resp *ocsp.Response, mtime time.Time, period time.Duration) bool {
	return needsRefresh(resp, mtime, period, time.Now())
}

func needsRefresh(resp *ocsp.Response, mtime time.Time, period time.Duration, now time.Time) bool {
	// TODO: take into account the signer certificate's NotAfter and NotBefore
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
func NeedsRefreshFile(filename string, issuer *x509.Certificate, period time.Duration) (bool, *Response, error) {
	stats, err := os.Stat(filename)
	if err != nil {
		return true, nil, err
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return true, nil, err
	}
	resp, err := ocsp.ParseResponse(data, issuer)
	if err != nil {
		return true, nil, err
	}
	mtime := stats.ModTime()
	// TODO: make check period configurable
	return NeedsRefresh(resp, mtime, period), &Response{
		OCSPResponse:    resp,
		RawOCSPResponse: data,
		LastModified:    mtime,
	}, nil
}
