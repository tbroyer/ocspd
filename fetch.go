package ocspd

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ocsp"
)

var (
	errCertExpired   = errors.New("ocspd: certificate is expired")
	errNoContentType = errors.New("ocspd: no response content-type")
)

type errBadHTTPStatus int

func (e errBadHTTPStatus) Error() string {
	return fmt.Sprintf("ocspd: bad http status: %d", e)
}

type errBadContentType string

func (e errBadContentType) Error() string {
	return fmt.Sprintf("ocspd: bad response content-type: %s", e)
}

type Request struct {
	url  string
	body []byte // if nil, method will be GET, otherwise method will be POST

	// The expiration time of the certificate (or the issuer if earlier)
	notAfter time.Time
	issuer   *x509.Certificate
}

func CreateRequest(cert, issuer *x509.Certificate, responderURL string) (req *Request, err error) {
	if responderURL == "" {
		responderURL, err = ResponderURL(cert)
		if err != nil {
			return nil, err
		}
		if responderURL == "" {
			responderURL, err = ResponderURL(issuer)
			if err != nil {
				return nil, err
			}
		}
	}

	r, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, err
	}

	notAfter := cert.NotAfter
	if issuer.NotAfter.Before(notAfter) {
		notAfter = issuer.NotAfter
	}

	getURL := responderURL
	if !strings.HasSuffix(getURL, "/") {
		getURL += "/"
	}
	getURL += strings.Replace(url.QueryEscape(base64.StdEncoding.EncodeToString(r)), "+", "%20", -1)
	if len(getURL) <= 255 {
		req = &Request{
			url:      getURL,
			notAfter: notAfter,
			issuer:   issuer,
		}
	} else {
		req = &Request{
			url:      responderURL,
			body:     r,
			notAfter: notAfter,
			issuer:   issuer,
		}
	}
	return req, nil
}

func (r *Request) createHTTPRequest(etag string, lastModified time.Time) (req *http.Request, err error) {
	if r.body == nil {
		if req, err = http.NewRequest("GET", r.url, nil); err != nil {
			return nil, err
		}
		switch {
		case etag != "":
			req.Header.Set("If-None-Match", etag)
		case !lastModified.IsZero():
			req.Header.Set("If-Modified-Since", lastModified.Format(http.TimeFormat))
		}
	} else {
		if req, err = http.NewRequest("POST", r.url, bytes.NewReader(r.body)); err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/ocsp-request")
	}
	return req, nil
}

type Response struct {
	OCSPResponse    *ocsp.Response
	RawOCSPResponse []byte
	MaxAge          time.Time
	Etag            string
	LastModified    time.Time
}

// A nil response with a nil error indicates a 304 Not Modified response.
func parseResponse(resp *http.Response, issuer *x509.Certificate, now time.Time) (*Response, error) {
	if resp.StatusCode == http.StatusNotModified {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errBadHTTPStatus(resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		return nil, errNoContentType
	}
	ct, p, err := mime.ParseMediaType(ct)
	if err != nil {
		return nil, err
	}
	if ct != "application/ocsp-response" || len(p) > 0 {
		return nil, errBadContentType(resp.Header.Get("Content-Type"))
	}
	bytes, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}
	or, err := ocsp.ParseResponse(bytes, issuer)
	if err != nil {
		return nil, err
	}
	r := &Response{
		OCSPResponse:    or,
		RawOCSPResponse: bytes,
		MaxAge:          maxAge(resp.Header, now),
		Etag:            resp.Header.Get("ETag"),
		LastModified:    lastModified(resp.Header),
	}
	return r, nil
}

func maxAge(h http.Header, now time.Time) time.Time {
	if cc, ok := h["Cache-Control"]; ok {
		now = serverDate(h, now)
		m := math.MaxInt64
		for _, c := range cc {
			for rest := c; rest != ""; {
				var k, v string
				k, v, rest = consumeCacheControlDirective(rest)
				switch k {
				case "max-age":
					if n, err := strconv.Atoi(v); n >= 0 && err == nil {
						if n == 0 {
							return now
						}
						if n < m {
							m = n
						}
					}
				case "no-cache":
					return now
				}
			}
		}
		if m != math.MaxInt64 {
			return now.Add(time.Duration(m) * time.Second)
		}
	}
	if eh := h.Get("Expires"); eh != "" {
		if e, err := http.ParseTime(eh); err == nil {
			return e
		}
	}
	return time.Time{}
}

// serverDate parses the Date header or returns now
func serverDate(h http.Header, now time.Time) time.Time {
	dStr := h.Get("Date")
	if dStr == "" {
		return now
	}
	if d, err := http.ParseTime(dStr); err == nil {
		return d
	}
	return now
}

func consumeCacheControlDirective(h string) (k, v, rest string) {
	if k, rest = consumeCacheControlKey(h); strings.HasPrefix(rest, "=") {
		v, rest = consumeCacheControlValue(strings.TrimLeftFunc(rest[1:], unicode.IsSpace))
	}
	if strings.HasPrefix(rest, ",") {
		rest = rest[1:]
	} else {
		rest = "" // malformed value, ignore the rest
	}
	return
}

func consumeCacheControlKey(h string) (string, string) {
	i := strings.IndexAny(h, `,=`)
	if i == -1 {
		return strings.TrimFunc(h, unicode.IsSpace), ""
	}
	return strings.ToLower(strings.TrimFunc(h[:i], unicode.IsSpace)), h[i:]
}

func consumeCacheControlValue(h string) (string, string) {
	h = strings.TrimLeftFunc(h, unicode.IsSpace)
	if !strings.HasPrefix(h, `"`) {
		i := strings.IndexRune(h, ',')
		if i == -1 {
			return h, ""
		}
		return strings.TrimFunc(h[:i], unicode.IsSpace), h[i:]
	}
	var inQuotedPair bool
	for i, r := range h[1:] {
		switch {
		case r == '\\':
			inQuotedPair = true
		case inQuotedPair:
			inQuotedPair = false
		case r == '"':
			return h[1 : i+1], strings.TrimLeftFunc(h[i+2:], unicode.IsSpace)
		}
	}
	// malformed quoted-pair
	return h, ""
}

func lastModified(h http.Header) time.Time {
	lmStr := h.Get("Last-Modified")
	if lmStr == "" {
		return time.Time{}
	}
	lm, _ := http.ParseTime(lmStr)
	return lm
}

type Fetcher struct {
	Client *http.Client

	time func() time.Time
}

func NewFetcher(client *http.Client) *Fetcher {
	return &Fetcher{
		Client: client,
	}
}

func (f *Fetcher) client() *http.Client {
	if f == nil || f.Client == nil {
		return http.DefaultClient
	}
	return f.Client
}

func (f *Fetcher) now() time.Time {
	if f == nil || f.time == nil {
		return time.Now()
	}
	return f.time()
}

func FetchForCert(cert, issuer *x509.Certificate, responderURL, etag string, lastModified, nextUpdate time.Time) (*Response, error) {
	req, err := CreateRequest(cert, issuer, responderURL)
	if err != nil {
		return nil, err
	}
	return Fetch(req, etag, lastModified, nextUpdate)
}

func FetchR(req *Request, prev *Response) (*Response, error) {
	return (*Fetcher)(nil).FetchR(req, prev)
}

func Fetch(req *Request, etag string, lastModified, nextUpdate time.Time) (*Response, error) {
	return (*Fetcher)(nil).Fetch(req, etag, lastModified, nextUpdate)
}

func (f *Fetcher) FetchR(req *Request, prev *Response) (*Response, error) {
	var etag string
	var lastModified, nextUpdate time.Time
	if prev != nil {
		etag, lastModified = prev.Etag, prev.LastModified
		if prev.OCSPResponse != nil {
			nextUpdate = prev.OCSPResponse.NextUpdate
		}
	}
	return f.Fetch(req, etag, lastModified, nextUpdate)
}

func (f *Fetcher) Fetch(req *Request, etag string, lastModified, nextUpdate time.Time) (*Response, error) {
	now := f.now()

	if now.After(req.notAfter) {
		return nil, errCertExpired
	}

	h, err := req.createHTTPRequest(etag, lastModified)
	if err != nil {
		return nil, err
	}
	r, err := f.client().Do(h)
	if err != nil {
		return nil, err
	}
	resp, err := parseResponse(r, req.issuer, now)
	if err != nil {
		return resp, err
	}

	// GET requests might be overzealously cached by intermediaries, reattempt if stale
	if h.Method == "GET" {
		if resp != nil {
			nextUpdate = resp.OCSPResponse.NextUpdate
		}
		if !nextUpdate.IsZero() && nextUpdate.Before(now) {
			h.Header.Set("Cache-Control", "no-cache")
			r, err = f.client().Do(h)
			if err != nil {
				// return previous response, even if stale (let it be handled downstream)
				return resp, nil
			}
			resp, err = parseResponse(r, req.issuer, now)
		}
	}

	return resp, err
}
