// Command r2notary is the independent verifier for R2Notary logs.
// It shares no code with the TypeScript writer; see PLAN.md §5.7.
//
// Exit codes:
//
//	0  success
//	1  verification failed: the log served data that does not verify (bad signature, corrupt
//	   tile or bundle, inconsistent or rolled-back checkpoint). This is evidence, not an outage.
//	2  usage error
//	3  verified, but the answer is negative: no entry for --key or --index, a --watch alert
//	   (monitor --once), or no audit has run (findings)
//	4  verification could not be completed (network error, HTTP error, local file error)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/mod/sumdb/note"

	"github.com/isaiahfoster/r2notary/cli/internal/cosign"
	"github.com/isaiahfoster/r2notary/cli/internal/monitor"
	"github.com/isaiahfoster/r2notary/cli/internal/tilefetch"
	"github.com/isaiahfoster/r2notary/cli/internal/verify"
	"github.com/isaiahfoster/r2notary/cli/internal/verr"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "0.0.0-dev"

const (
	exitOK       = 0
	exitFailure  = 1
	exitUsage    = 2
	exitNegative = 3
	exitError    = 4
)

// tokenEnv names the environment variable holding a private log's read token. A flag would put
// the token in shell history and process listings.
const tokenEnv = "R2NOTARY_TOKEN"

// blindingEnv holds a blinded log's KEY_BLINDING_KEY (M8), for the same reason.
const blindingEnv = "R2NOTARY_BLINDING_KEY"

const usage = `usage: r2notary <command> [flags]

  keygen      --name NAME [--out FILE]
  checkpoint  --log URL --vkey V [--out FILE]
  inclusion   --log URL --vkey V (--index N | --key K [--api URL] [--blinding-key-file F])
  consistency --log URL --vkey V --old FILE [--new FILE]
  monitor     --log URL --vkey V --state FILE [--watch PREFIX] [--interval 10s] [--once] [-q]
  findings    --log URL --vkey V --api URL
  version

--log is the log's URL prefix (https://host/log/<name>). --vkey is the verifier key, or @FILE.
--origin overrides the expected checkpoint origin (default: the vkey's name). For a private log,
put the read token in $R2NOTARY_TOKEN or pass --token-file FILE. --witness VKEY (repeatable, or
@FILE with one key per line) requires the live checkpoint to carry --witness-quorum (default 1)
valid cosignatures from those witnesses (C2SP tlog-witness). On a log that blinds key names,
--key needs the log's blinding key, in $R2NOTARY_BLINDING_KEY or --blinding-key-file FILE.
Run 'r2notary <command> -h' for details. Exit codes: 0 ok, 1 verification failed, 2 usage,
3 negative result (key not found, watch alert, no audit), 4 could not verify (network, HTTP,
files).
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	cmds := map[string]func(context.Context, []string, io.Writer, io.Writer) int{
		"keygen":      cmdKeygen,
		"checkpoint":  cmdCheckpoint,
		"inclusion":   cmdInclusion,
		"consistency": cmdConsistency,
		"monitor":     cmdMonitor,
		"findings":    cmdFindings,
	}
	if args[0] == "version" && len(args) == 1 {
		fmt.Fprintln(stdout, "r2notary", version)
		return exitOK
	}
	cmd, ok := cmds[args[0]]
	if !ok {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	return cmd(ctx, args[1:], stdout, stderr)
}

// exitFor reports err and maps it to an exit code.
func exitFor(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "r2notary:", err)
	var ie *verify.IndexError
	switch {
	case verr.IsFailure(err):
		return exitFailure
	case errors.As(err, &ie):
		return exitNegative // the entry does not exist (yet)
	case errors.Is(err, errUsage), errors.Is(err, monitor.ErrWatchBlinded):
		return exitUsage
	default:
		return exitError
	}
}

var errUsage = errors.New("usage error")

func usageErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errUsage, fmt.Sprintf(format, args...))
}

// logFlags are the flags every log-reading command takes.
type logFlags struct {
	log, vkey, origin, tokenFile string
	witnesses                    []string
	quorum                       int
}

func (f *logFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.log, "log", "", "log URL prefix, e.g. https://host/log/<name>")
	fs.StringVar(&f.vkey, "vkey", "", "verifier key, or @FILE to read it from a file")
	fs.StringVar(&f.origin, "origin", "", "expected checkpoint origin (default: the vkey's name)")
	fs.StringVar(&f.tokenFile, "token-file", "", "file holding the read token of a private log (else $"+tokenEnv+")")
	fs.Func("witness", "a witness's cosigner key (repeatable), or @FILE with one per line", func(s string) error {
		f.witnesses = append(f.witnesses, s)
		return nil
	})
	fs.IntVar(&f.quorum, "witness-quorum", -1, "cosignatures the live checkpoint needs from --witness keys (default 1; 0 only reports them)")
}

// witnessPolicy builds the witness policy from --witness and --witness-quorum.
func (f *logFlags) witnessPolicy() (verify.WitnessPolicy, error) {
	var keys []string
	for _, w := range f.witnesses {
		path, ok := strings.CutPrefix(w, "@")
		if !ok {
			keys = append(keys, w)
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return verify.WitnessPolicy{}, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				keys = append(keys, line)
			}
		}
	}
	p := verify.WitnessPolicy{Quorum: f.quorum}
	for _, k := range keys {
		v, err := cosign.NewVerifier(k)
		if err != nil {
			return p, usageErr("--witness %q: %v", k, err)
		}
		p.Witnesses = append(p.Witnesses, v)
	}
	switch {
	case len(p.Witnesses) == 0 && f.quorum > 0:
		return p, usageErr("--witness-quorum needs --witness")
	case p.Quorum < 0 && len(p.Witnesses) > 0:
		p.Quorum = 1
	case p.Quorum < 0:
		p.Quorum = 0
	case p.Quorum > len(p.Witnesses):
		return p, usageErr("--witness-quorum %d exceeds the %d witnesses given", p.Quorum, len(p.Witnesses))
	}
	return p, nil
}

// open builds a verify.Log from the flags.
func (f *logFlags) open() (*verify.Log, error) {
	if f.log == "" || f.vkey == "" {
		return nil, usageErr("--log and --vkey are required")
	}
	vkey := f.vkey
	if path, ok := strings.CutPrefix(vkey, "@"); ok {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		vkey = strings.TrimSpace(string(b))
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		return nil, usageErr("--vkey: %v", err)
	}
	token := os.Getenv(tokenEnv)
	if f.tokenFile != "" {
		b, err := os.ReadFile(f.tokenFile)
		if err != nil {
			return nil, err
		}
		token = strings.TrimSpace(string(b))
	}
	c, err := tilefetch.NewClient(f.log, token)
	if err != nil {
		return nil, usageErr("%v", err)
	}
	origin := f.origin
	if origin == "" {
		// R2Notary names its key after the origin (tlog-checkpoint SHOULD; DECISIONS D1.10).
		origin = v.Name()
	}
	policy, err := f.witnessPolicy()
	if err != nil {
		return nil, err
	}
	return &verify.Log{Client: c, Verifier: v, Origin: origin, Witness: policy}, nil
}

// parse parses a command's flags; a non-negative return is the exit code to stop with.
func parse(fs *flag.FlagSet, args []string, stderr io.Writer) int {
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "r2notary %s: unexpected argument %q\n", fs.Name(), fs.Arg(0))
		return exitUsage
	}
	return -1
}
