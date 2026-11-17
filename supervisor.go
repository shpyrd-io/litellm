package main

import (
	"io"
	"os/exec"
	"time"
)

// child is the LiteLLM process the program keeps. If it ends, the program
// ends with it and the platform starts the container again: a door with
// nothing behind it must not stay up.
type child struct {
	cmd  *exec.Cmd
	done chan error // receives the exit once, then closes
}

// startChild runs argv with the given output and its own process group.
func startChild(argv []string, env []string, out io.Writer) (*child, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = out, out
	prepare(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &child{cmd: cmd, done: make(chan error, 1)}
	go func() {
		c.done <- cmd.Wait()
		close(c.done)
	}()
	return c, nil
}

// Stop asks the process to finish and ends it when it has not within
// grace. It returns when the process is gone.
func (c *child) Stop(grace time.Duration) {
	select {
	case <-c.done:
		return
	default:
	}
	terminate(c.cmd)
	select {
	case <-c.done:
	case <-time.After(grace):
		kill(c.cmd)
		<-c.done
	}
}
