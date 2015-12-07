package ocspd

import (
	"reflect"
	"testing"
)

func TestParsePEM(t *testing.T) {
	for _, tt := range []string{"testdata/cert_only", "testdata/full"} {
		cert, issuer, err := ParsePEMCertificateBundle(tt)
		if err != nil {
			t.Fatal(err)
		}
		if cert.SerialNumber.Uint64() != 4455460921000457498 {
			t.Error("failed")
		}
		if issuer.SerialNumber.Uint64() != 146051 {
			t.Error("failed")
		}
		if !reflect.DeepEqual(cert.Issuer, issuer.Subject) {
			t.Error("failed")
		}
	}
}
