//go:build linux && amd64

package build

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func commandProcessNativeState(ctx context.Context, pid int) (string, error) {
	if ctx == nil || pid <= 0 {
		return "", errors.New("selected process context and positive identity are required")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", errors.Join(err, ctx.Err())
	}
	const maximum = 64 * 1024
	body, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr, ctx.Err()); err != nil {
		return "", err
	}
	if len(body) > maximum {
		return "", errors.New("selected process state exceeds its bound")
	}
	record := string(body)
	open, end := strings.IndexByte(record, '('), strings.LastIndexByte(record, ')')
	if open <= 0 || end <= open || end+1 >= len(record) || record[end+1] != ' ' {
		return "", errors.New("selected process state record is incomplete")
	}
	observed, err := strconv.Atoi(strings.TrimSpace(record[:open]))
	if err != nil || observed != pid {
		return "", fmt.Errorf("selected process state identity differs: pid=%d observed=%d", pid, observed)
	}
	fields := strings.Fields(record[end+1:])
	if len(fields) == 0 || len(fields[0]) != 1 || !strings.Contains("RSDZTtWXxKIP", fields[0]) {
		return "", errors.New("selected process state is invalid")
	}
	return fields[0], nil
}
