//go:build !darwin && !linux

package generator

func fixedDescriptors() bool { return false }
