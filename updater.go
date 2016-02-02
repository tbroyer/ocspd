package ocspd

import (
	"bytes"
	"errors"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

const DefaultTickRound = 5 * time.Minute

var ErrDuplicateTag = errors.New("ocspd: duplicate tag")

var defaultLogger = log.New(os.Stderr, "", log.LstdFlags)

type Event struct {
	Response    *ocsp.Response
	RawResponse []byte
	Tags        []string
}

type ocspStatus struct {
	// The prepared OCSP request corresponding to the certificate (and issuer)
	Request *Request
	// The last OCSP response, if any
	Response *Response
	// The next time the OCSP response will be refreshed (or zero if it needs to be refreshed asap)
	NextUpdate time.Time
	// The tags this status (certificate) is mapped to
	Tags []string
}

type ocspStatuses []*ocspStatus

func (s ocspStatuses) Len() int           { return len(s) }
func (s ocspStatuses) Swap(i, j int)      { s[j], s[i] = s[i], s[j] }
func (s ocspStatuses) Less(i, j int) bool { return s[i].NextUpdate.Before(s[j].NextUpdate) }

// Updater schedules queries to OCSP responders at appropriate times in order
// to maintain fresh OCSP responses for a set of certificates.
//
// Queries are scheduled such that the OCSP responses are always fresh but
// but without hammering the OCSP responders, hopefully making a single query
// at the appropriate time to get a fresh response (rather than the same that's
// already cached).
//
// Internally, Updater organizes certificates in such a way that if
// a certificate is added twice it won't cause more work to be done;
// a certificate can thus be associated to several "tags".
//
// Whenever the OCSP response for a certificate is refreshed, the
// OnUpdate function is called.
type Updater struct {
	OnUpdate  func(Event)
	TickRound time.Duration
	Logger    *log.Logger

	fetcher     *Fetcher
	mu          sync.Mutex
	statuses    ocspStatuses
	tagToStatus map[string]*ocspStatus
	timer       *time.Timer
	done        chan struct{}

	rand func(time.Duration) time.Duration
}

// NewUpdater creates a new Updater.
func NewUpdater(client *http.Client) *Updater {
	updater := &Updater{
		TickRound: DefaultTickRound,
		Logger:    defaultLogger,
		fetcher: &Fetcher{
			Client: client,
		},
		tagToStatus: make(map[string]*ocspStatus),
		done:        make(chan struct{}),
		rand:        defaultRand,
	}
	return updater
}

func defaultRand(d time.Duration) time.Duration {
	return time.Duration(rand.Int63n(int64(d)))
}

// AddOrUpdate adds a certificate to be monitored, with an optional response
// (generally coming from a cache).
//
// The OCSPResponse and MaxAge in resp will be used to schedule the next update,
// the ETag and LastModified will be used for the next update if provided;
// RawOCSPResponse is never used.
//
// If the certificate is already monitored, its next update will be rescheduled.
func (u *Updater) AddOrUpdate(tag string, req *Request, resp *Response) error {
	if tag == "" {
		panic("ocspd: empty tag")
	}
	if req == nil {
		panic("ocspd: nil request")
	}

	u.mu.Lock()
	defer u.mu.Unlock()
	// first do a lookup by tag, as it's the fastest and it checks for duplicate tags
	if s, ok := u.tagToStatus[tag]; ok {
		if !requestEqual(req, s.Request) {
			return ErrDuplicateTag
		}
		u.updateStatus(s, resp)
	} else {
		// lookup by OCSP request
		var found bool
		var s *ocspStatus
		for _, s = range u.statuses {
			if !requestEqual(req, s.Request) {
				continue
			}
			s.Tags = append(s.Tags, tag)
			sort.Strings(s.Tags)
			u.updateStatus(s, resp)
			if resp == nil && s.Response != nil && u.isStarted() {
				u.onUpdate(Event{
					Response:    s.Response.OCSPResponse,
					RawResponse: s.Response.RawOCSPResponse,
					Tags:        s.Tags,
				})
			}
			found = true
			break
		}
		if !found {
			// need to insert
			s = &ocspStatus{
				Request: req,
				Tags:    []string{tag},
			}
			u.updateStatus(s, resp)
			u.statuses = append(u.statuses, s)
		}
		u.tagToStatus[tag] = s
	}
	u.resetTimer()
	return nil
}

func requestEqual(a, b *Request) bool {
	// No need to compare the issuers, their information is included in the OCSP requests,
	// encoded into the url or body.
	return a.url == b.url &&
		(a.body == nil) == (b.body == nil) &&
		bytes.Equal(a.body, b.body)
}

func (u *Updater) Remove(tag string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if s, ok := u.tagToStatus[tag]; ok {
		delete(u.tagToStatus, tag)
		// remove the tag from OCSP status list of tags
		for i, t := range s.Tags {
			if t == tag {
				s.Tags = append(s.Tags[:i], s.Tags[i+1:]...)
				break
			}
		}
		if len(s.Tags) == 0 {
			// no tag left: we need to remove the OCSP status entirely
			for i := range u.statuses {
				if s == u.statuses[i] {
					u.statuses = append(u.statuses[:i], u.statuses[i+1:]...)
					break
				}
			}
		}
		u.Logger.Printf("%s no longer monitored\n", tag)
		u.resetTimer()
	}
}

// Start begins scheduling OCSP fetches for the monitored certificates.
//
// It schedules calls to UpdateNow at specific times to always maintain
// monitored certificates' OCSP responses up to date.
//
// It's a no-op if the Updater is already started, and blocks otherwise.
func (u *Updater) Start() {
	if !u.startTimer() {
		return
	}
	for {
		select {
		case <-u.timer.C:
			u.UpdateNow()
		case <-u.done:
			return
		}
	}
}

func (u *Updater) startTimer() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.isStarted() {
		return false
	}
	u.timer = time.NewTimer(math.MaxInt64)
	u.resetTimer()
	return true
}

func (u *Updater) isStarted() bool {
	return u.timer != nil
}

// Stop terminates the scheduled monitoring.
//
// It waits for ongoing fetches and only prevents future fetches from being scheduled.
func (u *Updater) Stop() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.isStarted() {
		return
	}
	u.timer.Stop()
	u.timer = nil
	u.done <- struct{}{}
}

func (u *Updater) resetTimer() {
	if !u.isStarted() {
		return
	}
	if len(u.statuses) == 0 {
		u.timer.Stop()
		return
	}
	sort.Sort(u.statuses)
	d := u.statuses[0].NextUpdate.Sub(u.fetcher.now())
	u.timer.Reset(d)
}

// UpdateNow fetches OCSP responses that needs to be refreshed.
func (u *Updater) UpdateNow() {
	u.mu.Lock()
	defer u.mu.Unlock()

	for _, s := range u.statuses {
		if s.NextUpdate.After(u.fetcher.now()) {
			break
		}
		tags := strings.Join(s.Tags, ", ")
		u.Logger.Printf("Fetching OCSP response for %s\n", tags)
		r, err := u.fetcher.FetchR(s.Request, s.Response)
		if err != nil {
			u.Logger.Printf("Error while fetching OCSP response for %s: %s\n", tags, err.Error())
			// retry asap
			// TODO: exponential backoff
			// TODO: skip other requests with same ResponderURL
			s.NextUpdate = s.NextUpdate.Add(u.TickRound)
		} else {
			if r == nil {
				u.Logger.Printf("Fetched OCSP response for %s: up-to-date.\n", tags)
			} else {
				u.Logger.Printf("Fetched OCSP response for %s\n", tags)
			}
			u.updateStatus(s, r)
			if r != nil {
				u.onUpdate(Event{
					Response:    r.OCSPResponse,
					RawResponse: r.RawOCSPResponse,
					Tags:        s.Tags,
				})
			}
		}
	}
	u.resetTimer()
}

func (u *Updater) updateStatus(s *ocspStatus, r *Response) {
	var resp *ocsp.Response
	var maxAge time.Time
	if r != nil {
		resp, maxAge = r.OCSPResponse, r.MaxAge
		s.Response = r
	}
	if !maxAge.IsZero() && (resp == nil || maxAge.Before(resp.NextUpdate)) {
		s.NextUpdate = maxAge
		u.Logger.Printf("Update of %s scheduled at %v\n", strings.Join(s.Tags, ","), s.NextUpdate)
	} else if resp != nil {
		now := u.fetcher.now()
		if resp.NextUpdate.Before(now) {
			// update asap
			s.NextUpdate = time.Time{}
			u.Logger.Printf("Update of %s scheduled asap\n", strings.Join(s.Tags, ","))
		} else {
			earliest := now.Add(u.TickRound)
			h := resp.NextUpdate.Sub(earliest) / 2
			s.NextUpdate = earliest.Add(h + u.rand(h)).Truncate(u.TickRound)
			u.Logger.Printf("Update of %s scheduled at %v\n", strings.Join(s.Tags, ","), s.NextUpdate)
		}
	} else if s.Response == nil {
		// update asap
		s.NextUpdate = time.Time{}
		u.Logger.Printf("Update of %s scheduled asap\n", strings.Join(s.Tags, ","))
	}
}

func (u *Updater) onUpdate(event Event) {
	if u.OnUpdate != nil {
		go u.OnUpdate(event)
	}
}
