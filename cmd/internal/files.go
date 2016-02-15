package internal

import (
	"os"
	"path/filepath"
	"strings"
)

func ShouldIgnoreFileName(n string) bool {
	return strings.HasSuffix(n, ".issuer") || strings.HasSuffix(n, ".ocsp") || strings.HasSuffix(n, ".sctl") || strings.HasSuffix(n, ".key")
}

func FileNames(args []string) (files []string, dirs []string, err error) {
	for _, arg := range args {
		stats, err := os.Stat(arg)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return files, dirs, err
		}
		if stats.IsDir() {
			f, err := os.Open(arg)
			if err != nil {
				if os.IsNotExist(err) {
					// dir has disappeared between Stat and Open,
					// let's do as if it never existed
					continue
				}
				return files, dirs, err
			}
			dirs = append(dirs, arg)
			ns, err := f.Readdirnames(-1)
			f.Close()
			if err != nil {
				return files, dirs, err
			}
			for _, n := range ns {
				if ShouldIgnoreFileName(n) {
					continue
				}
				n = filepath.Join(arg, n)
				stats, err := os.Stat(n)
				if err != nil {
					if os.IsNotExist(err) {
						// n has disappeared between Readdirnames and Open,
						// let's do as if it never existed
						continue
					}
					return files, dirs, err
				}
				if stats.Mode().IsRegular() {
					files = append(files, n)
				}
			}
		} else if stats.Mode().IsRegular() {
			files = append(files, arg)
		}
	}
	return files, dirs, nil
}
