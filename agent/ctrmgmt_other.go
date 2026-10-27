//go:build !linux

package main

func runOp(a OpArgs) OpResult { return failRes(resUnsupport, "управление контейнерами поддерживается только на Linux") }

func collectImages() []ImgInfo { return nil }
