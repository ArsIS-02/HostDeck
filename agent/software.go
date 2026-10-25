package main

import "time"

// SoftwareItem — одна запись списка установленного ПО.
type SoftwareItem struct {
	Name    string `json:"n"`
	Version string `json:"v,omitempty"`
	Source  string `json:"s"` // app | brew | cask | pkg
	Path    string `json:"p,omitempty"`
}

func nowUnix() int64 { return time.Now().Unix() }
