//go:build darwin

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

func collectSoftware() []SoftwareItem {
	var items []SoftwareItem
	if o, err := run(150*time.Second, "/usr/sbin/system_profiler", "-json", "SPApplicationsDataType"); err == nil || len(o) > 0 {
		var r struct {
			Apps []struct {
				Name    string `json:"_name"`
				Version string `json:"version"`
				Path    string `json:"path"`
				From    string `json:"obtained_from"`
			} `json:"SPApplicationsDataType"`
		}
		if json.Unmarshal([]byte(o), &r) == nil {
			for _, a := range r.Apps {
				items = append(items, SoftwareItem{Name: a.Name, Version: a.Version, Source: "app", Path: a.Path})
			}
		}
	}
	// Homebrew: читаем каталоги напрямую — `brew` отказывается работать от root.
	for _, root := range []string{"/opt/homebrew", "/usr/local"} {
		items = append(items, listDirVersions(filepath.Join(root, "Cellar"), "brew")...)
		items = append(items, listDirVersions(filepath.Join(root, "Caskroom"), "cask")...)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items
}

func listDirVersions(dir, src string) []SoftwareItem {
	var out []SoftwareItem
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		it := SoftwareItem{Name: e.Name(), Source: src, Path: filepath.Join(dir, e.Name())}
		if vs, err := os.ReadDir(it.Path); err == nil && len(vs) > 0 {
			it.Version = vs[len(vs)-1].Name()
		}
		out = append(out, it)
	}
	return out
}
