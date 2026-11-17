//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// prepare gives the process a group of its own, so that LiteLLM and what it
// starts are ended together.
func prepare(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

func terminate(cmd *exec.Cmd) { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }

func kill(cmd *exec.Cmd) { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
