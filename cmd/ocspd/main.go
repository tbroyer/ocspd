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
	"gopkg.in/fsnotify.v1"
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

	files, dirs, err := internal.FileNames(flag.Args())
	if err != nil {
		log.Fatal(err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	updater := ocspd.NewUpdater(nil)
	updater.TickRound = tickRound

	for _, dir := range dirs {
		if err := watcher.Add(dir); err != nil {
			log.Fatal(err)
		}
	}

	for _, file := range files {
		if err := addOrUpdate(file, watcher, updater); err != nil {
			log.Fatal(err)
		}
	}

	updater.OnUpdate = func(ev ocspd.Event) {
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
	}

	go updater.Start()

	for {
		select {
		case ev := <-watcher.Events:
			if ev.Op&fsnotify.Remove == fsnotify.Remove || ev.Op&fsnotify.Rename == fsnotify.Rename {
				for _, suffix := range []string{".ocsp", ".issuer"} {
					if strings.HasSuffix(ev.Name, suffix) {
						log.Println(ev.Name, " removed, rescheduling")
						addOrUpdate(strings.TrimSuffix(ev.Name, suffix), watcher, updater)
						break
					}
				}
				if !internal.ShouldIgnoreFileName(ev.Name) {
					updater.Remove(ev.Name)
				}
			}
			if ev.Op&fsnotify.Create == fsnotify.Create || ev.Op&fsnotify.Write == fsnotify.Write {
				var certName = ev.Name
				if strings.HasSuffix(ev.Name, ".issuer") {
					certName = strings.TrimSuffix(ev.Name, ".issuer")
				}
				if internal.ShouldIgnoreFileName(certName) {
					break
				}
				if !isRegularFile(ev.Name) || (certName != ev.Name && !isRegularFile(certName)) {
					break
				}
				err := addOrUpdate(certName, watcher, updater)
				if err != nil {
					log.Println(certName, ": ", err)
				}
			}
		case err := <-watcher.Errors:
			log.Println(err)
		}
	}
}

func addOrUpdate(file string, watcher *fsnotify.Watcher, updater *ocspd.Updater) error {
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

	err = watcher.Add(file)
	if err != nil {
		return err
	}
	return updater.AddOrUpdate(file, req, resp)
}

func isRegularFile(f string) bool {
	stats, err := os.Stat(f)
	if err != nil {
		log.Println(f, ": ", err)
		return false
	}
	return stats.Mode().IsRegular()
}
