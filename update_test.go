package ocspd

import (
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestNeedsRefresh(t *testing.T) {
	now := time.Now()
	type testcase struct {
		name     string
		expected bool
		mtime    time.Time
		period   time.Duration
		response ocsp.Response
	}
	var tests = []testcase{
		{
			name:     "No NextUpdate",
			expected: true,
			response: ocsp.Response{
				Status:     ocsp.Good,
				ProducedAt: now.Add(-96 * time.Hour),
				ThisUpdate: now.Add(-96 * time.Hour),
			},
		},
		{
			name:     "In first half of validity period",
			expected: false,
			mtime:    now.Add(-12 * time.Hour),
			period:   12 * time.Hour,
			response: ocsp.Response{
				Status:     ocsp.Good,
				ProducedAt: now.Add(-24 * time.Hour),
				ThisUpdate: now.Add(-24 * time.Hour),
				NextUpdate: now.Add(72 * time.Hour),
			},
		},
		{
			name:     "Response would be expired next time we'll check", // despite being in the first half of validity period
			expected: true,
			mtime:    now.Add(-12 * time.Hour),
			period:   96 * time.Hour,
			response: ocsp.Response{
				Status:     ocsp.Good,
				ProducedAt: now.Add(-24 * time.Hour),
				ThisUpdate: now.Add(-24 * time.Hour),
				NextUpdate: now.Add(72 * time.Hour),
			},
		},
		{
			name:     "In second half of validity period, never refreshed",
			expected: true,
			mtime:    now.Add(-12 * time.Hour),
			period:   12 * time.Hour,
			response: ocsp.Response{
				Status:     ocsp.Good,
				ProducedAt: now.Add(-49 * time.Hour),
				ThisUpdate: now.Add(-49 * time.Hour),
				NextUpdate: now.Add(47 * time.Hour),
			},
		},
		{
			name:     "In second half of validity period, already refreshed",
			expected: false,
			mtime:    now.Add(-12 * time.Hour),
			period:   12 * time.Hour,
			response: ocsp.Response{
				Status:     ocsp.Good,
				ProducedAt: now.Add(-73 * time.Hour),
				ThisUpdate: now.Add(-73 * time.Hour),
				NextUpdate: now.Add(23 * time.Hour),
			},
		},
		// TODO: test with different statuses
	}
	for _, test := range tests {
		if needsRefresh(&test.response, test.mtime, test.period, now) != test.expected {
			var expected, actual string
			if test.expected {
				expected, actual = "need refresh", "didn't"
			} else {
				expected, actual = "not need refresh", "did"
			}
			t.Errorf("%s: expected to %s but %s", test.name, expected, actual)
		}
	}
}
