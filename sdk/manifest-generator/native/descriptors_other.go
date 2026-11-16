//go:build !darwin && !linux

package native

func fixedDescriptors() bool { return false }
