//go:build windows

package main

import "os/exec"

// The image runs on Linux; on Windows the program only has to build and be
// tested, and a process cannot be asked to finish, only ended.
func prepare(cmd *exec.Cmd) {}

func terminate(cmd *exec.Cmd) { _ = cmd.Process.Kill() }

func kill(cmd *exec.Cmd) { _ = cmd.Process.Kill() }
