// update-ocsp reads an all-in-one bundle file (whose name is passed as a
// command-line argument) and send a query to the OCSP responder, storing the
// response in a *.ocsp file next to the input file.
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/crypto/ocsp"

	"github.com/tbroyer/ocspd"
)

func main() {
	// TODO: validate number of arguments
	certBundleFileName := os.Args[1]
	cert, issuer, err := ocspd.ParsePEMCertificateBundle(certBundleFileName)
	if err != nil {
		log.Fatal(err)
	}
	// TODO: check existing OCSP response before querying the responder
	data, err := ocspd.Update(cert, issuer, "")
	if err != nil {
		log.Fatal(err)
	}
	resp, err := ocsp.ParseResponse(data, issuer)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v: %v\n", certBundleFileName, statusString(resp.Status))
	fmt.Printf("\tThis Update: %v\n", resp.ThisUpdate)
	if !resp.NextUpdate.IsZero() {
		fmt.Printf("\tNext Update: %v\n", resp.NextUpdate)
	}
	if resp.Status == ocsp.Revoked {
		fmt.Printf("\tReason: %v\n", revocationReasonString(resp.RevocationReason))
		fmt.Printf("\tRevocation Time: %v\n", resp.RevokedAt)
	}
	err = ioutil.WriteFile(certBundleFileName+".ocsp", data, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func statusString(status int) string {
	switch status {
	case ocsp.Good:
		return "good"
	case ocsp.Unknown:
		return "unknown"
	case ocsp.Revoked:
		return "revoked"
	default:
		log.Panicf("Unknown status %v", status)
		return ""
	}
}

func revocationReasonString(revocationReason int) string {
	switch revocationReason {
	case ocsp.Unspecified:
		return "unspecified"
	case ocsp.KeyCompromise:
		return "keyCompromise"
	case ocsp.CACompromise:
		return "cACompromise"
	case ocsp.AffiliationChanged:
		return "affiliationChanged"
	case ocsp.Superseded:
		return "superseded"
	case ocsp.CessationOfOperation:
		return "cessationOfOperation"
	case ocsp.CertificateHold:
		return "certificateHold"
	case ocsp.RemoveFromCRL:
		return "removeFromCRL"
	case ocsp.PrivilegeWithdrawn:
		return "privilegeWithdrawn"
	case ocsp.AACompromise:
		return "aACompromise"
	default:
		log.Panicf("Unknown revocation reason %v", revocationReason)
		return ""
	}
}
