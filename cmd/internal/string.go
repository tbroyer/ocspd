package internal

import (
	"golang.org/x/crypto/ocsp"
)

var statusString = map[int]string{
	ocsp.Good:    "good",
	ocsp.Unknown: "unknown",
	ocsp.Revoked: "revoked",
}

func StatusString(status int) string {
	s, ok := statusString[status]
	if !ok {
		s = "<unknown status>"
	}
	return s
}

var revocationReasonString = map[int]string{
	ocsp.Unspecified:          "unspecified",
	ocsp.KeyCompromise:        "keyCompromise",
	ocsp.CACompromise:         "cACompromise",
	ocsp.AffiliationChanged:   "affiliationChanged",
	ocsp.Superseded:           "superseded",
	ocsp.CessationOfOperation: "cessationOfOperation",
	ocsp.CertificateHold:      "certificateHold",
	ocsp.RemoveFromCRL:        "removeFromCRL",
	ocsp.PrivilegeWithdrawn:   "privilegeWithdrawn",
	ocsp.AACompromise:         "aACompromise",
}

func RevocationReasonString(revocationReason int) string {
	r, ok := revocationReasonString[revocationReason]
	if !ok {
		r = "<unknown revocation reason>"
	}
	return r
}
