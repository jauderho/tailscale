// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/peterbourgon/ff/v3/ffcli"
	"golang.org/x/time/rate"
	"inet.af/netaddr"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/version"
)

var fileCmd = &ffcli.Command{
	Name:       "file",
	ShortUsage: "file <cp|get> ...",
	ShortHelp:  "Send or receive files",
	Subcommands: []*ffcli.Command{
		fileCpCmd,
		fileGetCmd,
	},
	Exec: func(context.Context, []string) error {
		// TODO(bradfitz): is there a better ffcli way to
		// annotate subcommand-required commands that don't
		// have an exec body of their own?
		return errors.New("file subcommand required; run 'tailscale file -h' for details")
	},
}

var fileCpCmd = &ffcli.Command{
	Name:       "cp",
	ShortUsage: "file cp <files...> <target>:",
	ShortHelp:  "Copy file(s) to a host",
	Exec:       runCp,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("cp")
		fs.StringVar(&cpArgs.name, "name", "", "alternate filename to use, especially useful when <file> is \"-\" (stdin)")
		fs.BoolVar(&cpArgs.verbose, "verbose", false, "verbose output")
		fs.BoolVar(&cpArgs.targets, "targets", false, "list possible file cp targets")
		return fs
	})(),
}

var cpArgs struct {
	name    string
	verbose bool
	targets bool
}

func runCp(ctx context.Context, args []string) error {
	if cpArgs.targets {
		return runCpTargets(ctx, args)
	}
	if len(args) < 2 {
		return errors.New("usage: tailscale file cp <files...> <target>:")
	}
	files, target := args[:len(args)-1], args[len(args)-1]
	if !strings.HasSuffix(target, ":") {
		return fmt.Errorf("final argument to 'tailscale file cp' must end in colon")
	}
	target = strings.TrimSuffix(target, ":")
	hadBrackets := false
	if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		hadBrackets = true
		target = strings.TrimSuffix(strings.TrimPrefix(target, "["), "]")
	}
	if ip, err := netaddr.ParseIP(target); err == nil && ip.Is6() && !hadBrackets {
		return fmt.Errorf("an IPv6 literal must be written as [%s]", ip)
	} else if hadBrackets && (err != nil || !ip.Is6()) {
		return errors.New("unexpected brackets around target")
	}
	ip, _, err := tailscaleIPFromArg(ctx, target)
	if err != nil {
		return err
	}

	stableID, isOffline, err := getTargetStableID(ctx, ip)
	if err != nil {
		return fmt.Errorf("can't send to %s: %v", target, err)
	}
	if isOffline {
		fmt.Fprintf(Stderr, "# warning: %s is offline\n", target)
	}

	if len(files) > 1 {
		if cpArgs.name != "" {
			return errors.New("can't use --name= with multiple files")
		}
		for _, fileArg := range files {
			if fileArg == "-" {
				return errors.New("can't use '-' as STDIN file when providing filename arguments")
			}
		}
	}

	for _, fileArg := range files {
		var fileContents io.Reader
		var name = cpArgs.name
		var contentLength int64 = -1
		if fileArg == "-" {
			fileContents = os.Stdin
			if name == "" {
				name, fileContents, err = pickStdinFilename()
				if err != nil {
					return err
				}
			}
		} else {
			f, err := os.Open(fileArg)
			if err != nil {
				if version.IsSandboxedMacOS() {
					return errors.New("the GUI version of Tailscale on macOS runs in a macOS sandbox that can't read files")
				}
				return err
			}
			defer f.Close()
			fi, err := f.Stat()
			if err != nil {
				return err
			}
			if fi.IsDir() {
				return errors.New("directories not supported")
			}
			contentLength = fi.Size()
			fileContents = io.LimitReader(f, contentLength)
			if name == "" {
				name = filepath.Base(fileArg)
			}

			if envknob.Bool("TS_DEBUG_SLOW_PUSH") {
				fileContents = &slowReader{r: fileContents}
			}
		}

		if cpArgs.verbose {
			log.Printf("sending %q to %v/%v/%v ...", name, target, ip, stableID)
		}
		err := tailscale.PushFile(ctx, stableID, contentLength, name, fileContents)
		if err != nil {
			return err
		}
		if cpArgs.verbose {
			log.Printf("sent %q", name)
		}
	}
	return nil
}

func getTargetStableID(ctx context.Context, ipStr string) (id tailcfg.StableNodeID, isOffline bool, err error) {
	ip, err := netaddr.ParseIP(ipStr)
	if err != nil {
		return "", false, err
	}
	fts, err := tailscale.FileTargets(ctx)
	if err != nil {
		return "", false, err
	}
	for _, ft := range fts {
		n := ft.Node
		for _, a := range n.Addresses {
			if a.IP() != ip {
				continue
			}
			isOffline = n.Online != nil && !*n.Online
			return n.StableID, isOffline, nil
		}
	}
	return "", false, fileTargetErrorDetail(ctx, ip)
}

// fileTargetErrorDetail returns a non-nil error saying why ip is an
// invalid file sharing target.
func fileTargetErrorDetail(ctx context.Context, ip netaddr.IP) error {
	found := false
	if st, err := tailscale.Status(ctx); err == nil && st.Self != nil {
		for _, peer := range st.Peer {
			for _, pip := range peer.TailscaleIPs {
				if pip == ip {
					found = true
					if peer.UserID != st.Self.UserID {
						return errors.New("owned by different user; can only send files to your own devices")
					}
				}
			}
		}
	}
	if found {
		return errors.New("target seems to be running an old Tailscale version")
	}
	if !tsaddr.IsTailscaleIP(ip) {
		return fmt.Errorf("unknown target; %v is not a Tailscale IP address", ip)
	}
	return errors.New("unknown target; not in your Tailnet")
}

const maxSniff = 4 << 20

func ext(b []byte) string {
	if len(b) < maxSniff && utf8.Valid(b) {
		return ".txt"
	}
	if exts, _ := mime.ExtensionsByType(http.DetectContentType(b)); len(exts) > 0 {
		return exts[0]
	}
	return ""
}

// pickStdinFilename reads a bit of stdin to return a good filename
// for its contents. The returned Reader is the concatenation of the
// read and unread bits.
func pickStdinFilename() (name string, r io.Reader, err error) {
	sniff, err := io.ReadAll(io.LimitReader(os.Stdin, maxSniff))
	if err != nil {
		return "", nil, err
	}
	return "stdin" + ext(sniff), io.MultiReader(bytes.NewReader(sniff), os.Stdin), nil
}

type slowReader struct {
	r  io.Reader
	rl *rate.Limiter
}

func (r *slowReader) Read(p []byte) (n int, err error) {
	const burst = 4 << 10
	plen := len(p)
	if plen > burst {
		plen = burst
	}
	if r.rl == nil {
		r.rl = rate.NewLimiter(rate.Limit(1<<10), burst)
	}
	n, err = r.r.Read(p[:plen])
	r.rl.WaitN(context.Background(), n)
	return
}

func runCpTargets(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("invalid arguments with --targets")
	}
	fts, err := tailscale.FileTargets(ctx)
	if err != nil {
		return err
	}
	for _, ft := range fts {
		n := ft.Node
		var detail string
		if n.Online != nil {
			if !*n.Online {
				detail = "offline"
			}
		} else {
			detail = "unknown-status"
		}
		if detail != "" && n.LastSeen != nil {
			d := time.Since(*n.LastSeen)
			detail += fmt.Sprintf("; last seen %v ago", d.Round(time.Minute))
		}
		if detail != "" {
			detail = "\t" + detail
		}
		printf("%s\t%s%s\n", n.Addresses[0].IP(), n.ComputedName, detail)
	}
	return nil
}

var fileGetCmd = &ffcli.Command{
	Name:       "get",
	ShortUsage: "file get [--wait] [--verbose] <target-directory>",
	ShortHelp:  "Move files out of the Tailscale file inbox",
	Exec:       runFileGet,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("get")
		fs.BoolVar(&getArgs.wait, "wait", false, "wait for a file to arrive if inbox is empty")
		fs.BoolVar(&getArgs.verbose, "verbose", false, "verbose output")
		return fs
	})(),
}

var getArgs struct {
	wait    bool
	verbose bool
}

func runFileGet(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: file get <target-directory>")
	}
	log.SetFlags(0)

	dir := args[0]
	if dir == "/dev/null" {
		return wipeInbox(ctx)
	}

	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return fmt.Errorf("%q is not a directory", dir)
	}

	var wfs []apitype.WaitingFile
	var err error
	for {
		wfs, err = tailscale.WaitingFiles(ctx)
		if err != nil {
			return fmt.Errorf("getting WaitingFiles: %w", err)
		}
		if len(wfs) != 0 || !getArgs.wait {
			break
		}
		if getArgs.verbose {
			log.Printf("waiting for file...")
		}
		if err := waitForFile(ctx); err != nil {
			return err
		}
	}

	deleted := 0
	for _, wf := range wfs {
		rc, size, err := tailscale.GetWaitingFile(ctx, wf.Name)
		if err != nil {
			return fmt.Errorf("opening inbox file %q: %v", wf.Name, err)
		}
		targetFile := filepath.Join(dir, wf.Name)
		of, err := os.OpenFile(targetFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			if _, err := os.Stat(targetFile); err == nil {
				return fmt.Errorf("refusing to overwrite %v", targetFile)
			}
			return err
		}
		_, err = io.Copy(of, rc)
		rc.Close()
		if err != nil {
			return fmt.Errorf("failed to write %v: %v", targetFile, err)
		}
		if err := of.Close(); err != nil {
			return err
		}
		if getArgs.verbose {
			log.Printf("wrote %v (%d bytes)", wf.Name, size)
		}
		if err := tailscale.DeleteWaitingFile(ctx, wf.Name); err != nil {
			return fmt.Errorf("deleting %q from inbox: %v", wf.Name, err)
		}
		deleted++
	}
	if getArgs.verbose {
		log.Printf("moved %d files", deleted)
	}
	return nil
}

func wipeInbox(ctx context.Context) error {
	if getArgs.wait {
		return errors.New("can't use --wait with /dev/null target")
	}
	wfs, err := tailscale.WaitingFiles(ctx)
	if err != nil {
		return fmt.Errorf("getting WaitingFiles: %w", err)
	}
	deleted := 0
	for _, wf := range wfs {
		if getArgs.verbose {
			log.Printf("deleting %v ...", wf.Name)
		}
		if err := tailscale.DeleteWaitingFile(ctx, wf.Name); err != nil {
			return fmt.Errorf("deleting %q: %v", wf.Name, err)
		}
		deleted++
	}
	if getArgs.verbose {
		log.Printf("deleted %d files", deleted)
	}
	return nil
}

func waitForFile(ctx context.Context) error {
	c, bc, pumpCtx, cancel := connect(ctx)
	defer cancel()
	fileWaiting := make(chan bool, 1)
	bc.SetNotifyCallback(func(n ipn.Notify) {
		if n.ErrMessage != nil {
			fatalf("Notify.ErrMessage: %v\n", *n.ErrMessage)
		}
		if n.FilesWaiting != nil {
			select {
			case fileWaiting <- true:
			default:
			}
		}
	})
	go pump(pumpCtx, bc, c)
	select {
	case <-fileWaiting:
		return nil
	case <-pumpCtx.Done():
		return pumpCtx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}
