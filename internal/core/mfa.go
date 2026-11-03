package core

// The optional authentication helper is a separate, unprivileged process. The
// GUI remains pure Go. Its private framed protocol is documented alongside the
// helper; no human-readable OpenConnect output is parsed for MFA prompts.
import (
	"bytes"
	"context"
	"crypto/rand"
	wire "encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	mfaMaxFrame   = 65536
	mfaMaxRounds  = 8
	mfaMaxFields  = 16
	mfaMaxChoices = 32
	mfaTimeout    = 180 * time.Second
)

type AuthChoice struct{ ID, Label string }
type AuthField struct {
	ID, Label, Kind string
	Choices         []AuthChoice
}
type AuthChallenge struct {
	SessionID      string
	Round          uint16
	Title, Message string
	Fields         []AuthField
}
type AuthAnswer struct {
	SessionID string
	Round     uint16
	Values    map[string][]byte
}

// AuthPrompt must stop when ctx is canceled. The bridge consumes and clears
// answer Values on return. A callback must not retain those byte slices.
type AuthPrompt func(context.Context, AuthChallenge) (AuthAnswer, error)

type MFAHelper struct {
	executable string
	cap        Capability
}

func NewMFAHelper() *MFAHelper {
	h := &MFAHelper{}
	h.cap.Message = "Interactive authentication requires the optional meridian-auth-helper and libopenconnect 9.12 or newer."
	if runtime.GOOS != "linux" {
		return h
	}
	// Prefer a packaged sibling, then a normal administrator/user PATH install.
	if executable, err := os.Executable(); err == nil {
		if executable, err = filepath.EvalSymlinks(executable); err == nil {
			sibling := filepath.Join(filepath.Dir(executable), "meridian-auth-helper")
			if trustedMFAHelperPath(sibling) {
				return newMFAHelperAt(sibling)
			}
		}
	}
	if path, err := exec.LookPath("meridian-auth-helper"); err == nil && trustedMFAHelperPath(path) {
		return newMFAHelperAt(path)
	}
	return h
}
func newMFAHelperAt(path string) *MFAHelper {
	h := &MFAHelper{executable: path, cap: Capability{Message: "Interactive authentication helper is unavailable or has an incompatible protocol.", Executable: path}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := (execRunner{}).Run(ctx, path, []string{"--protocol-version"}, nil)
	if err == nil && bytes.Equal(out, []byte("meridian-auth-helper/1\n")) {
		h.cap = Capability{true, "Structured interactive authentication is available; gateway MFA compatibility still requires verification.", path}
	}
	return h
}
func (h *MFAHelper) Capability() Capability {
	if h == nil {
		return Capability{Message: "Interactive authentication helper is unavailable."}
	}
	return h.cap
}

func (h *MFAHelper) Authenticate(ctx context.Context, p Profile, c Credentials, prompt AuthPrompt) (map[string]string, error) {
	if !h.Capability().Available {
		return nil, errors.New(h.Capability().Message)
	}
	if prompt == nil {
		return nil, errors.New("interactive authentication prompt is unavailable")
	}
	if err := ValidateProfile(p); err != nil {
		return nil, err
	}
	if err := validateCredentials(p, c); err != nil {
		return nil, err
	}
	if p.Protocol != "anyconnect" {
		return nil, errors.New("interactive authentication currently supports AnyConnect only")
	}
	if p.ProxyURL != "" && !p.AllowProxySystemAuth {
		return nil, errors.New("proxy requires explicit per-connection consent")
	}
	files, ca, cert, key, err := mfaFiles(p)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, mfaTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.executable)
	cmd.Env = isolatedCommandEnvironment(os.Environ())
	cmd.ExtraFiles = files
	cmd.Stderr = nil // Never retain untrusted or secret-bearing diagnostics.
	cmd.WaitDelay = 2 * time.Second
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, errors.New("authentication pipe unavailable")
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, errors.New("authentication pipe unavailable")
	}
	if err = cmd.Start(); err != nil {
		in.Close()
		return nil, errors.New("authentication helper could not start")
	}
	watchDone := make(chan struct{})
	watchStopped := make(chan struct{})
	defer func() { close(watchDone); <-watchStopped }()
	go func() {
		defer close(watchStopped)
		select {
		case <-ctx.Done():
			_ = in.Close()
			_ = out.Close()
		case <-watchDone:
		}
	}()
	waited := false
	defer func() {
		cancel()
		in.Close()
		out.Close()
		if !waited {
			_ = cmd.Wait()
		}
	}()
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return nil, errors.New("authentication session unavailable")
	}
	sessionID := hex.EncodeToString(id[:])
	init := mfaHeader(1, sessionID, 0)
	for _, v := range []string{p.Gateway, ca, p.ProxyURL, cert, key} {
		init = mfaAppend(init, []byte(v))
	}
	init = mfaAppend(init, c.KeyPassword)
	init = mfaAppend(init, []byte(p.AuthGroup))
	err = mfaWrite(in, init)
	clear(init)
	if err != nil {
		return nil, mfaError(ctx)
	}
	for round := uint16(1); round <= mfaMaxRounds+1; round++ {
		frame, err := mfaRead(out)
		if err != nil {
			return nil, mfaError(ctx)
		}
		typ, roundID, reader, err := mfaDecodeHeader(frame, sessionID)
		if err != nil {
			clear(frame)
			return nil, err
		}
		if typ == 4 {
			// Result carries the last completed round, including zero for cert-only auth.
			if roundID != round-1 {
				clear(frame)
				return nil, errors.New("authentication result has a stale round")
			}
			fields := make(map[string]string, 4)
			for _, name := range []string{"COOKIE", "CONNECT_URL", "FINGERPRINT", "RESOLVE"} {
				value, e := reader.text(16384)
				if e != nil || (strings.Contains(value, "'") || hasControl(value)) {
					clear(frame)
					return nil, errors.New("invalid authentication result")
				}
				fields[name] = value
			}
			clear(frame)
			if reader.Len() != 0 || fields["COOKIE"] == "" || fields["FINGERPRINT"] == "" || ValidateProfile(Profile{Name: "auth", Protocol: "anyconnect", Gateway: fields["CONNECT_URL"]}) != nil || !validMFAResolve(fields["CONNECT_URL"], fields["RESOLVE"]) {
				return nil, errors.New("invalid authentication result")
			}
			in.Close()
			err = cmd.Wait()
			waited = true
			if err != nil {
				return nil, mfaError(ctx)
			}
			return fields, nil
		}
		if typ != 2 || roundID != round || round > mfaMaxRounds {
			clear(frame)
			return nil, errors.New("authentication helper failed or exceeded its round limit")
		}
		challenge, err := mfaChallenge(reader, sessionID, round)
		clear(frame)
		if err != nil {
			return nil, err
		}
		answer, auto := initialMFAAnswer(challenge, p, c)
		if !auto {
			answer, err = prompt(ctx, challenge)
		}
		if err != nil {
			clearAuthAnswer(answer)
			return nil, mfaError(ctx)
		}
		reply, err := mfaAnswer(challenge, answer)
		clearAuthAnswer(answer)
		if err != nil {
			return nil, err
		}
		err = mfaWrite(in, reply)
		clear(reply)
		if err != nil {
			return nil, mfaError(ctx)
		}
	}
	return nil, errors.New("authentication exceeded its round limit")
}

func mfaError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.New("interactive authentication failed; check credentials, certificate trust and supported gateway authentication")
}
func clearAuthAnswer(a AuthAnswer) {
	for _, v := range a.Values {
		clear(v)
	}
}
func initialMFAAnswer(ch AuthChallenge, p Profile, c Credentials) (AuthAnswer, bool) {
	a := AuthAnswer{SessionID: ch.SessionID, Round: ch.Round, Values: map[string][]byte{}}
	if ch.Round != 1 || len(c.Password) == 0 {
		return a, false
	}
	for _, f := range ch.Fields {
		switch {
		case f.ID == "username" && f.Kind == "text" && p.Username != "":
			a.Values[f.ID] = []byte(p.Username)
		case f.ID == "password" && f.Kind == "password":
			a.Values[f.ID] = bytes.Clone(c.Password)
		default:
			clearAuthAnswer(a)
			return AuthAnswer{}, false
		}
	}
	return a, len(a.Values) > 0
}

// mfaFiles retains checked file descriptors until the child exits. Neither
// paths selected by the server nor secret contents are used as command args.
func mfaFiles(p Profile) (files []*os.File, ca, cert, key string, err error) {
	defer func() {
		if err != nil {
			for _, f := range files {
				f.Close()
			}
		}
	}()
	if p.CAFile != "" {
		var f *os.File
		f, err = openValidatedCAFile(p.CAFile)
		if err != nil {
			return
		}
		files = append(files, f)
		ca = "/proc/self/fd/3"
	}

	var pair []*os.File
	pair, err = openClientCertificate(p)
	if err != nil {
		return
	}
	if p.CertificateFormat == "pkcs11" {
		cert, key = p.ClientCertificate, p.ClientKey
	}
	for i, f := range pair {
		path := fmt.Sprintf("/proc/self/fd/%d", 3+len(files))
		files = append(files, f)
		if i == 0 {
			cert = path
		} else {
			key = path
		}
	}
	return
}

type mfaReader struct{ *bytes.Reader }

func (r mfaReader) u16() (uint16, error) {
	var n uint16
	err := wire.Read(r.Reader, wire.BigEndian, &n)
	return n, err
}
func (r mfaReader) text(max int) (string, error) {
	n, err := r.u16()
	if err != nil || int(n) > max || int(n) > r.Len() {
		return "", errors.New("invalid authentication field length")
	}
	b := make([]byte, n)
	_, err = io.ReadFull(r, b)
	if err != nil || !utf8.Valid(b) {
		clear(b)
		return "", errors.New("invalid authentication text")
	}
	for _, v := range string(b) {
		if unicode.IsControl(v) && v != '\n' && v != '\t' {
			clear(b)
			return "", errors.New("invalid authentication text")
		}
	}
	s := string(b)
	clear(b)
	return s, nil
}
func mfaHeader(typ byte, id string, round uint16) []byte {
	b := append([]byte{1, typ}, []byte(id)...)
	return wire.BigEndian.AppendUint16(b, round)
}
func mfaAppend(b, value []byte) []byte {
	b = wire.BigEndian.AppendUint16(b, uint16(len(value)))
	return append(b, value...)
}
func mfaWrite(w io.Writer, b []byte) error {
	if len(b) < 36 || len(b) > mfaMaxFrame {
		return errors.New("authentication frame exceeds limit")
	}
	prefix := wire.BigEndian.AppendUint32(nil, uint32(len(b)))
	if _, err := io.Copy(w, bytes.NewReader(prefix)); err != nil {
		return err
	}
	_, err := io.Copy(w, bytes.NewReader(b))
	return err
}
func mfaRead(r io.Reader) ([]byte, error) {
	var n uint32
	if err := wire.Read(r, wire.BigEndian, &n); err != nil {
		return nil, err
	}
	if n < 36 || n > mfaMaxFrame {
		return nil, errors.New("invalid authentication frame size")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	if err != nil {
		clear(b)
		return nil, err
	}
	return b, nil
}
func mfaDecodeHeader(b []byte, id string) (byte, uint16, mfaReader, error) {
	if len(b) < 36 || b[0] != 1 || string(b[2:34]) != id {
		return 0, 0, mfaReader{}, errors.New("authentication session mismatch")
	}
	return b[1], wire.BigEndian.Uint16(b[34:36]), mfaReader{bytes.NewReader(b[36:])}, nil
}
func mfaChallenge(r mfaReader, id string, round uint16) (AuthChallenge, error) {
	ch := AuthChallenge{SessionID: id, Round: round}
	var err error
	ch.Title, err = r.text(2048)
	if err != nil {
		return ch, err
	}
	ch.Message, err = r.text(4096)
	if err != nil {
		return ch, err
	}
	n, err := r.u16()
	if err != nil || n == 0 || n > mfaMaxFields {
		return ch, errors.New("unsupported authentication form")
	}
	seen := map[string]bool{}
	for range n {
		f := AuthField{}
		f.ID, err = r.text(128)
		if err != nil || f.ID == "" || hasControl(f.ID) || seen[f.ID] {
			return ch, errors.New("invalid authentication field")
		}
		seen[f.ID] = true
		f.Label, err = r.text(2048)
		if err != nil {
			return ch, err
		}
		kind, e := r.ReadByte()
		if e != nil {
			return ch, e
		}
		switch kind {
		case 1:
			f.Kind = "text"
		case 2:
			f.Kind = "password"
		case 3:
			f.Kind = "select"
		default:
			return ch, errors.New("unsupported authentication field type")
		}
		count, e := r.u16()
		if e != nil || count > mfaMaxChoices || (kind == 3 && count == 0) || (kind != 3 && count != 0) {
			return ch, errors.New("invalid authentication choices")
		}
		choices := map[string]bool{}
		for range count {
			choice := AuthChoice{}
			choice.ID, err = r.text(128)
			if err != nil || choice.ID == "" || hasControl(choice.ID) || choices[choice.ID] {
				return ch, errors.New("invalid authentication choice")
			}
			choices[choice.ID] = true
			choice.Label, err = r.text(2048)
			if err != nil {
				return ch, err
			}
			f.Choices = append(f.Choices, choice)
		}
		ch.Fields = append(ch.Fields, f)
	}
	if r.Len() != 0 {
		return ch, errors.New("unexpected authentication frame data")
	}
	return ch, nil
}
func mfaAnswer(ch AuthChallenge, a AuthAnswer) ([]byte, error) {
	if a.SessionID != ch.SessionID || a.Round != ch.Round || len(a.Values) != len(ch.Fields) {
		return nil, errors.New("authentication answer is stale or incomplete")
	}
	b := mfaHeader(3, ch.SessionID, ch.Round)
	b = wire.BigEndian.AppendUint16(b, uint16(len(ch.Fields)))
	for _, f := range ch.Fields {
		v, ok := a.Values[f.ID]
		if !ok || len(v) > 4096 || !utf8.Valid(v) || hasControl(string(v)) {
			clear(b)
			return nil, errors.New("invalid authentication answer")
		}
		if f.Kind == "select" {
			valid := false
			for _, choice := range f.Choices {
				if bytes.Equal(v, []byte(choice.ID)) {
					valid = true
				}
			}
			if !valid {
				clear(b)
				return nil, errors.New("invalid authentication choice")
			}
		}
		b = mfaAppend(b, []byte(f.ID))
		b = mfaAppend(b, v)
	}
	if len(b) > mfaMaxFrame {
		clear(b)
		return nil, errors.New("authentication answer exceeds limit")
	}
	return b, nil
}

// A non-empty resolver hint pins only the authenticated hostname to a numeric IP.
func validMFAResolve(gateway, resolve string) bool {
	if resolve == "" {
		return true
	}
	u, err := url.Parse(gateway)
	if err != nil {
		return false
	}
	host, address, ok := strings.Cut(resolve, ":")
	return ok && strings.EqualFold(host, u.Hostname()) && net.ParseIP(address) != nil
}
