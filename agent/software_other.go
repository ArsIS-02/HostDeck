//go:build !darwin

package main

import (
	"strings"
	"time"
)

// collectSoftware для Linux — для проверки цепочки вне Mac (dpkg или rpm).
func collectSoftware() []SoftwareItem {
	var items []SoftwareItem
	if o, err := run(30*time.Second, "dpkg-query", "-W", "-f", "${Package}\t${Version}\n"); err == nil {
		for _, ln := range strings.Split(o, "\n") {
			if f := strings.SplitN(ln, "\t", 2); len(f) == 2 {
				items = append(items, SoftwareItem{Name: f[0], Version: f[1], Source: "pkg"})
			}
		}
	} else if o, err := run(30*time.Second, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"); err == nil {
		for _, ln := range strings.Split(o, "\n") {
			if f := strings.SplitN(ln, "\t", 2); len(f) == 2 {
				items = append(items, SoftwareItem{Name: f[0], Version: f[1], Source: "pkg"})
			}
		}
	}
	return items
}
