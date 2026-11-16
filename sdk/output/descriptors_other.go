//go:build !darwin && !linux

package output

func fixedDescriptors(bool) bool { return false }
