package main

import (
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestHelperProcess is the program the supervisor tests run: this test
// binary, asked to behave.
func TestHelperProcess(t *testing.T) {
	switch os.Getenv("DOOR_HELPER") {
	case "":
		return
	case "exit3":
		os.Stdout.WriteString("helper: bye\n")
		os.Exit(3)
	case "sleep":
		time.Sleep(time.Minute)
	case "stubborn":
		signal.Ignore(syscall.SIGTERM)
		time.Sleep(time.Minute)
	}
	os.Exit(0)
}

func helper(t *testing.T, mode string, out *syncBuf) *child {
	t.Helper()
	c, err := startChild([]string{os.Args[0], "-test.run=^TestHelperProcess$"}, append(os.Environ(), "DOOR_HELPER="+mode), out)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Stop(time.Second) })
	return c
}

func TestTheProgramSeesTheChildEnd(t *testing.T) {
	out := &syncBuf{}
	c := helper(t, "exit3", out)
	select {
	case err := <-c.done:
		if err == nil || !strings.Contains(err.Error(), "3") {
			t.Fatalf("exit: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the child's end was not seen")
	}
	if !strings.Contains(out.String(), "helper: bye") {
		t.Fatalf("output: %q", out.String())
	}
}

func TestStopEndsTheChild(t *testing.T) {
	c := helper(t, "sleep", &syncBuf{})
	start := time.Now()
	c.Stop(5 * time.Second)
	select {
	case <-c.done:
	default:
		t.Fatal("Stop returned with the child running")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("Stop took %v", time.Since(start))
	}
}

func TestStopKillsAChildThatIgnoresTheRequest(t *testing.T) {
	c := helper(t, "stubborn", &syncBuf{})
	time.Sleep(500 * time.Millisecond) // let the helper install its handler
	start := time.Now()
	c.Stop(300 * time.Millisecond)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Stop took %v", d)
	}
}
