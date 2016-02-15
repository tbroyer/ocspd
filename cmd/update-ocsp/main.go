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
	"time"

	"github.com/tbroyer/ocspd"
	"github.com/tbroyer/ocspd/cmd/internal"
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

	names, _, err := internal.FileNames(flag.Args())
	if err != nil {
		log.Fatal(err)
	}

	for _, certBundleFileName := range names {
		cert, issuer, err := internal.ParsePEMCertificateBundle(certBundleFileName)
		if err != nil {
			log.Print(certBundleFileName, ": ", err)
			exitCode = 1
			continue
		}
		req, err := ocspd.CreateRequest(cert, issuer, "")
		if err != nil {
			log.Println(certBundleFileName, ": ", err)
			exitCode = 1
			continue
		}
		// check existing/cached OCSP response before querying the responder
		ocspFileName := certBundleFileName + ".ocsp"
		needsRefresh, resp, err := ocspd.NeedsRefreshFile(ocspFileName, issuer, interval)
		if err != nil {
			log.Println(certBundleFileName, ": ", err)
			exitCode = 1
			continue
		}
		if !needsRefresh {
			// cached response is "fresh" enough, don't refresh it
			continue
		}

		resp, err = ocspd.FetchR(req, resp)
		if err != nil {
			log.Println(certBundleFileName, ": ", err)
			exitCode = 1
			continue
		}
		if resp == nil {
			// conditional GET returned 304 Not Modified, update mtime for next check
			now := time.Now()
			os.Chtimes(ocspFileName, now, now)
			continue
		}
		internal.PrintOCSPResponse(certBundleFileName, resp.OCSPResponse)
		if err = ioutil.WriteFile(ocspFileName, resp.RawOCSPResponse, 0644); err != nil {
			log.Print(certBundleFileName, ": ", err)
			exitCode = 1
			continue
		}
		if hookCmd != "" {
			if err = internal.RunHookCmd(hookCmd, resp.RawOCSPResponse, os.Stdout, os.Stderr); err != nil {
				log.Println(certBundleFileName, ": ", err)
				exitCode = 1
				continue
			}
		}
	}
	os.Exit(exitCode)
}

func statusString(status int) string {
	s := internal.StatusString(status)
	if s == "" {
		log.Panicf("Unknown status %v", status)
	}
	return s
}

func revocationReasonString(revocationReason int) string {
	r := internal.RevocationReasonString(revocationReason)
	if r == "" {
		log.Panicf("Unknown revocation reason %v", revocationReason)
	}
	return r
}
