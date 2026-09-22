//go:build linux

package listener

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLinuxUnprivilegedSocketSharing(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("separate-UID/group witness requires root; no system accounts are created")
	}
	base, err := os.MkdirTemp("", "authd-access-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	if err = os.Chmod(base, 0711); err != nil {
		t.Fatal(err)
	}
	// A fresh copy of this test executable is traversable by the fixture users;
	// the go test runner's private build directory normally is not.
	binary := filepath.Join(base, "witness")
	in, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(binary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0555)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal(copyErr, closeErr)
	}
	dir := filepath.Join(base, "run")
	if err = os.Mkdir(dir, 0711); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(dir, 65533, 65533); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s")
	child := exec.Command(binary, "-test.run=^TestLinuxAccessChild$")
	child.Env = append(os.Environ(), "AUTHD_ACCESS_CHILD=serve", "AUTHD_ACCESS_PATH="+path)
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65533, Gid: 65533, Groups: []uint32{65532}}}
	pipe, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = os.Stderr
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	ready := make(chan string, 1)
	go func() {
		scan := bufio.NewScanner(pipe)
		if scan.Scan() {
			ready <- scan.Text()
		} else {
			ready <- ""
		}
	}()
	select {
	case result := <-ready:
		if result != "ready" {
			t.Fatal("unprivileged bind/group selection failed", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("unprivileged server timeout")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid != 65533 || stat.Gid != 65532 || info.Mode().Perm() != 0660 {
		t.Fatal("wrong published owner/group/mode", info)
	}
	for _, granted := range []bool{false, true} {
		cmd := exec.Command(binary, "-test.run=^TestLinuxAccessChild$")
		cmd.Env = append(os.Environ(), "AUTHD_ACCESS_CHILD=dial", "AUTHD_ACCESS_PATH="+path)
		cred := &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}
		if granted {
			cred.Groups = []uint32{65532}
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
		body, err := cmd.CombinedOutput()
		if (err == nil) != granted {
			t.Fatalf("proxy group=%v: err=%v output=%s", granted, err, body)
		}
	}
}

func TestLinuxAccessChild(t *testing.T) {
	path := os.Getenv("AUTHD_ACCESS_PATH")
	switch os.Getenv("AUTHD_ACCESS_CHILD") {
	case "serve":
		ln, err := Open(Options{Address: path, UnixMode: 0660, UnixGroup: "65532"})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		fmt.Println("ready")
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(conn, "permitted")
			_ = conn.Close()
		}
	case "dial":
		conn, err := net.DialTimeout("unix", path, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		data, err := io.ReadAll(conn)
		if err != nil || string(data) != "permitted" {
			t.Fatal("wrong server response", string(data), err)
		}
	}
}
