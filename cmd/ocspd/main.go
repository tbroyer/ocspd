package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/tbroyer/ocspd"
	"github.com/tbroyer/ocspd/cmd/internal"
	"golang.org/x/crypto/ocsp"
)

var tickRound time.Duration
var hookCmd string

func init() {
	const (
		tickRoundUsage = "minimum interval between 'ticks'"
		hookUsage      = "optional program to run if all goes well"
	)
	flag.DurationVar(&tickRound, "tick", ocspd.DefaultTickRound, tickRoundUsage)
	flag.DurationVar(&tickRound, "t", ocspd.DefaultTickRound, tickRoundUsage+" (shorthand)")

	flag.StringVar(&hookCmd, "hook", "", hookUsage)
	flag.StringVar(&hookCmd, "h", "", hookUsage+" (shorthand)")
}

func main() {
	flag.Parse()

	names, err := internal.FileNames(flag.Args())
	if err != nil {
		log.Fatal(err)
	}

	updater := &ocspd.Updater{
		TickRound: tickRound,
		Log:       log.Printf,

		OnUpdate: func(ev ocspd.Event) {
			tags := strings.Join(ev.Tags, ", ")
			internal.PrintOCSPResponse(tags, ev.Response)
			for _, f := range ev.Tags {
				ocspFilename := f + ".ocsp"
				if err := ioutil.WriteFile(ocspFilename, ev.RawResponse, 0644); err != nil {
					log.Println(f, ": ", err)
					break
				}
				// "store" ThisUpdate as file's mtime as a hint for next daemon restart
				_ = os.Chtimes(ocspFilename, ev.Response.ThisUpdate, ev.Response.ThisUpdate)
			}
			if hookCmd != "" {
				if err := internal.RunHookCmd(hookCmd, ev.RawResponse, os.Stdout, os.Stderr); err != nil {
					log.Println(tags, ": ", err)
				}
			}
		},
	}

	for _, file := range names {
		if err := addOrUpdate(file, updater); err != nil {
			log.Fatal(err)
		}
	}

	updater.Start()
}

func addOrUpdate(file string, updater *ocspd.Updater) error {
	updater.Remove(file)

	cert, issuer, err := internal.ParsePEMCertificateBundle(file)
	if err != nil {
		return err
	}
	req, err := ocspd.CreateRequest(cert, issuer, "")
	if err != nil {
		return err
	}
	var resp *ocspd.Response
	ocspFilename := file + ".ocsp"
	if stats, err := os.Stat(ocspFilename); err == nil {
		resp = &ocspd.Response{
			LastModified: stats.ModTime(),
		}
		if resp.RawOCSPResponse, err = ioutil.ReadFile(ocspFilename); err == nil {
			if resp.OCSPResponse, err = ocsp.ParseResponse(resp.RawOCSPResponse, issuer); err != nil {
				resp = nil // make sure resp is nil if there was an error
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	} // else: leave resp==nil

	return updater.AddOrUpdate(file, req, resp)
}
