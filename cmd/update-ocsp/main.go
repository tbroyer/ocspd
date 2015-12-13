// update-ocsp reads all-in-one bundle files (whose names are passed as
// command-line argument) and sends queries to the OCSP responders, storing the
// responses in *.ocsp files next to the input files.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/tbroyer/ocspd"
)

var interval = flag.Duration("interval", 24*time.Hour, "indicative interval between invocations of this tool")
var hookCmd = flag.String("hook", "", "optional program to run if all goes well")

func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "Missing certificate filename(s)")
		flag.Usage()
		os.Exit(2)
	}
	exitCode := 0
	for _, certBundleFileName := range flag.Args() {
		cert, issuer, err := ocspd.ParsePEMCertificateBundle(certBundleFileName)
		if err != nil {
			log.Println(certBundleFileName, ": ", err)
			exitCode = 1
			continue
		}
		// check existing/cached OCSP response before querying the responder
		ocspFileName := certBundleFileName + ".ocsp"
		needsRefresh, err := ocspd.NeedsRefreshFile(ocspFileName, issuer, *interval)
		if err != nil {
			log.Println(certBundleFileName, ": ", err)
			exitCode = 1
			continue
		}
		if !needsRefresh {
			// cached response is "fresh" enough, don't refresh it
			continue
		}
		data, err := ocspd.Update(cert, issuer, "")
		if err != nil {
			log.Println(certBundleFileName, ": ", err)
			exitCode = 1
			continue
		}
		resp, err := ocsp.ParseResponse(data, issuer)
		if err != nil {
			log.Println(certBundleFileName, ": ", err)
			exitCode = 1
			continue
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
		if err = ioutil.WriteFile(ocspFileName, data, 0644); err != nil {
			log.Print(certBundleFileName, ": ", err)
			exitCode = 1
			continue
		}
		if len(*hookCmd) > 0 {
			if err = ocspd.RunHookCmd(*hookCmd, data, os.Stdout, os.Stderr); err != nil {
				log.Println(certBundleFileName, ": ", err)
				exitCode = 1
				continue
			}
		}
	}
	os.Exit(exitCode)
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
