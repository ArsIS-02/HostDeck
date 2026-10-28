//go:build !linux && !darwin

package main

func readNetPlat() netPlat { return netPlat{} }
