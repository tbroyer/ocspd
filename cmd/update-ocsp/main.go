// update-ocsp reads all-in-one bundle files (whose names are passed as
// command-line argument) and sends queries to the OCSP responders, storing the
// responses in *.ocsp files next to the input files.
// The argument can also identify a directory, in which case all files in the
// directory (with the exception of those ending in .ocsp, .issuer, or .sctl
// –for HAProxy compatibility–, or .key –for compatibility with almost anything
// else, storing private keys separately–) are treated as input files.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/tbroyer/ocspd"
)

var interval time.Duration
var hookCmd string

func init() {
	const (
		defaultInterval = 24 * time.Hour
		intervalUsage   = "indicative interval between invocations of this tool"
		hookUsage       = "optional program to run if all goes well"
	)
	flag.DurationVar(&interval, "interval", defaultInterval, intervalUsage)
	flag.DurationVar(&interval, "i", defaultInterval, intervalUsage+" (shorthand)")

	flag.StringVar(&hookCmd, "hook", "", hookUsage)
	flag.StringVar(&hookCmd, "h", "", hookUsage+" (shorthand)")
}

var exitCode = 0

func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "Missing certificate filename(s)")
		flag.Usage()
		os.Exit(2)
	}
	var names = fileNames()
	for _, certBundleFileName := range names {
		cert, issuer, err := ocspd.ParsePEMCertificateBundle(certBundleFileName)
		if err != nil {
			log.Println(certBundleFileName, ": ", err)
			exitCode = 1
			continue
		}
		// check existing/cached OCSP response before querying the responder
		ocspFileName := certBundleFileName + ".ocsp"
		needsRefresh, err := ocspd.NeedsRefreshFile(ocspFileName, issuer, interval)
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
		if hookCmd != "" {
			if err = ocspd.RunHookCmd(hookCmd, data, os.Stdout, os.Stderr); err != nil {
				log.Println(certBundleFileName, ": ", err)
				exitCode = 1
				continue
			}
		}
	}
	os.Exit(exitCode)
}

func fileNames() (names []string) {
	for _, arg := range flag.Args() {
		stats, err := os.Stat(arg)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			log.Fatal(err)
		}
		if stats.IsDir() {
			f, err := os.Open(arg)
			if os.IsNotExist(err) {
				// dir has disappeared between Stat and Open,
				// let's do as if it never existed
				continue
			}
			if err != nil {
				log.Fatal(err)
			}
			ns, err := f.Readdirnames(-1)
			f.Close()
			if err != nil {
				log.Fatal(err)
			}
			for _, n := range ns {
				if strings.HasSuffix(n, ".issuer") || strings.HasSuffix(n, ".ocsp") || strings.HasSuffix(n, ".sctl") || strings.HasSuffix(n, ".key") {
					continue
				}
				n = filepath.Join(arg, n)
				stats, err := os.Stat(n)
				if os.IsNotExist(err) {
					// n has disappeared between Readdirnames and Open,
					// let's do as if it never existed
					continue
				}
				if err != nil {
					log.Fatal(err)
				}
				if stats.Mode().IsRegular() {
					names = append(names, n)
				}
			}
		} else if stats.Mode().IsRegular() {
			names = append(names, arg)
		}
	}
	return
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
