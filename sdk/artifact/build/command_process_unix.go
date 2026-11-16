//go:build (darwin && arm64) || (linux && amd64)

package build

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
	"time"
)

const goCommandSettlement = 5 * time.Second

func runGoCommand(ctx context.Context, command *exec.Cmd) (settled bool, resultErr error) {
	if ctx == nil {
		return true, errors.New("go command context is required")
	}
	if err := ctx.Err(); err != nil {
		return true, err
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	command.WaitDelay = time.Second
	if err := ctx.Err(); err != nil {
		return true, err
	}
	if err := command.Start(); err != nil {
		return true, errors.Join(err, ctx.Err())
	}
	defer func() { resultErr = errors.Join(resultErr, ctx.Err()) }()
	pid := command.Process.Pid
	if pid <= 0 {
		return false, errors.Join(errGoCommandUnsettled, errors.New("go command process identity is invalid"))
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	var observationErr error
observe:
	for {
		exited, err := goCommandChildExited(pid)
		if err != nil {
			if errors.Is(err, syscall.ECHILD) {
				return false, errors.Join(errGoCommandUnsettled, err)
			}
			observationErr = err
			break
		}
		if exited {
			break
		}
		select {
		case <-ctx.Done():
			break observe
		case <-tick.C:
		}
	}
	// Keep the leader unreaped until this one destructive group signal. Its PID
	// cannot be reused here; later group checks never send another signal.
	deadline := time.Now().Add(goCommandSettlement)
	signalErr := syscall.Kill(-pid, syscall.SIGKILL)
	horizon := time.NewTimer(time.Until(deadline))
	defer horizon.Stop()
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	var waitErr error
	select {
	case waitErr = <-wait:
	case <-horizon.C:
		return false, errors.Join(errGoCommandUnsettled, observationErr, signalErr)
	}
	for {
		if !time.Now().Before(deadline) {
			return false, errors.Join(errGoCommandUnsettled, observationErr, signalErr, waitErr)
		}
		groupErr := syscall.Kill(-pid, 0)
		if errors.Is(groupErr, syscall.ESRCH) {
			// Darwin can report EPERM for an existing group of only zombies.
			// Accept that provisional result only after Wait and group absence.
			if errors.Is(signalErr, syscall.ESRCH) || errors.Is(signalErr, syscall.EPERM) {
				signalErr = nil
			}
			return true, errors.Join(observationErr, signalErr, waitErr)
		}
		if groupErr != nil && !errors.Is(groupErr, syscall.EPERM) && !errors.Is(groupErr, syscall.EINTR) {
			return false, errors.Join(errGoCommandUnsettled, observationErr, signalErr, waitErr, groupErr)
		}
		select {
		case <-horizon.C:
			return false, errors.Join(errGoCommandUnsettled, observationErr, signalErr, waitErr)
		case <-tick.C:
		}
	}
}

func goCommandTerminalEvent(pid int, signal, child, code int32) (bool, error) {
	if child == 0 && signal == 0 && code == 0 {
		return false, nil
	}
	if int(child) != pid || signal != int32(syscall.SIGCHLD) {
		return false, errors.New("go command wait identity differs")
	}
	switch code {
	case 1, 2, 3:
		return true, nil
	case 4, 5, 6:
		// Darwin may report a stopped child even with WEXITED; it is not done.
		return false, nil
	default:
		return false, errors.New("go command wait state is unsupported")
	}
}
