package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mygo-vpn/internal/core"
	"os"
	"runtime"
	"time"
	"unicode/utf8"
)

func foregroundVPNSupported() bool { return runtime.GOOS == "linux" }

// Credential input is deliberately not accepted on argv, through the environment,
// or from an echoing terminal. A caller can pipe it from a trusted secret manager.
// The reader owns input for this command and closes it on cancellation.
func readCredentialInput(ctx context.Context, input *os.File) (core.Credentials, error) {
	if err := ctx.Err(); err != nil {
		return core.Credentials{}, err
	}
	st, err := input.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice != 0 {
		return core.Credentials{}, errors.New("credentials require a non-terminal input stream")
	}
	cancelRead := context.AfterFunc(ctx, func() { _ = input.Close() })
	defer cancelRead()
	type result struct {
		credentials core.Credentials
		err error
	}
	// Inherited stdin can be a blocking descriptor not managed by Go's poller.
	// Closing it is best effort, so cancellation must not wait for Read to return.
	// The worker exclusively owns its buffers and either hands them to the caller
	// or clears them. The unbuffered channel prevents abandoned secret results.
	results := make(chan result)
	go func() {
		data, err := io.ReadAll(io.LimitReader(input, 16385))
		defer clear(data)
		var credentials core.Credentials
		if err != nil || len(data) > 16384 {
			err = errors.New("credential input failed or exceeded its limit")
		} else if ctx.Err() == nil {
			credentials, err = decodeCredentials(data)
		} else {
			err = ctx.Err()
		}
		select {
		case results <- result{credentials, err}:
		case <-ctx.Done():
			clearCredentials(credentials)
		}
	}()
	select {
	case result := <-results:
		return result.credentials, result.err
	case <-ctx.Done():
		return core.Credentials{}, ctx.Err()
	}
}

func decodeCredentials(data []byte) (core.Credentials, error) {
	if len(data) > 16384 || !utf8.Valid(data) {
		return core.Credentials{}, errors.New("credential input exceeded its limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return core.Credentials{}, errors.New("invalid credential input")
	}
	var credentials core.Credentials
	valid := false
	defer func() {
		if !valid {
			clearCredentials(credentials)
		}
	}()
	seen := make(map[string]bool)
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || seen[key] {
			return core.Credentials{}, errors.New("invalid credential input")
		}
		seen[key] = true
		valueToken, err := decoder.Token()
		value, ok := valueToken.(string)
		if err != nil || !ok || len(value) > 4096 {
			return core.Credentials{}, errors.New("invalid credential input")
		}
		switch key {
		case "password":
			credentials.Password = []byte(value)
		case "ipsec_psk":
			credentials.IPsecPSK = []byte(value)
		case "key_password":
			credentials.KeyPassword = []byte(value)
		default:
			return core.Credentials{}, errors.New("invalid credential input")
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return core.Credentials{}, errors.New("invalid credential input")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return core.Credentials{}, errors.New("invalid credential input")
	}
	valid = true
	return credentials, nil
}

func clearCredentials(c core.Credentials) {
	clear(c.Password)
	clear(c.IPsecPSK)
	clear(c.KeyPassword)
}

func (a application) connect(ctx context.Context, path string, args []string, out, errOut io.Writer) (code int) {
	f := newFlags("connect")
	index := f.Int("profile", 0, "1-based profile index")
	authorized := f.Bool("authorize-network", false, "Authorize authentication and route/DNS changes for this session")
	stdin := f.Bool("credentials-stdin", false, "Read credential JSON from non-terminal stdin")
	interactive := f.Bool("interactive-auth", false, "Allow hidden MFA prompts on the controlling terminal")
	if !parseFlags(f, args) || *index < 1 || !*authorized || !*stdin {
		return usageError(errOut)
	}
	if a.vpnSupported == nil || !a.vpnSupported() || a.vpnAdapter == nil || a.credentials == nil {
		return failure(errOut, "Foreground VPN is available only on Linux with NetworkManager.")
	}
	cfg, exists, err := loadConfig(path)
	if err != nil || !exists || *index > len(cfg.Profiles) {
		return failure(errOut, "Cannot load the selected profile; validate the configuration and profile index.")
	}
	p := cfg.Profiles[*index-1]
	if p.InteractiveAuth && !*interactive {
		return failure(errOut, "Interactive profiles require --interactive-auth and a foreground controlling terminal.")
	}
	if *interactive && !p.InteractiveAuth {
		return usageError(errOut)
	}
	if p.Protocol != "anyconnect" && p.Protocol != "l2tp" {
		return failure(errOut, "This foreground backend supports only AnyConnect and L2TP/IPsec profiles.")
	}
	if ctx.Err() != nil {
		return 0
	}
	var terminal authTerminal
	if p.InteractiveAuth {
		if a.authTerminal == nil {
			return failure(errOut, "Interactive authentication requires a supported Linux controlling terminal.")
		}
		terminal, err = a.authTerminal()
		if err != nil {
			return failure(errOut, "Cannot open a safe foreground controlling terminal. No authentication was started.")
		}
		defer func() {
			if err := terminal.Close(); err != nil {
				code = failure(errOut, "Terminal restoration could not be confirmed. Reset the terminal before continuing.")
			}
		}()
	}
	credentials, err := a.credentials(ctx)
	defer clearCredentials(credentials)
	if ctx.Err() != nil {
		return 0
	}
	if err != nil {
		return failure(errOut, "Could not read credential JSON from non-terminal stdin. No tunnel was started.")
	}
	adapter := a.vpnAdapter()
	if ctx.Err() != nil {
		return 0
	}
	if terminal != nil {
		prompter, ok := adapter.(interface{ SetAuthPrompt(core.AuthPrompt) })
		if !ok {
			return failure(errOut, "The selected backend does not support interactive authentication.")
		}
		prompter.SetAuthPrompt(terminal.Prompt)
	}
	e := core.NewEngine(adapter)
	if err := e.ConnectWithCredentials(p, credentials, true); err != nil {
		return failure(errOut, "Connection could not start; check profile, credentials and installed backend prerequisites.")
	}
	clearCredentials(credentials)
	return runForegroundSession(ctx, e, out, errOut)
}

// The foreground process owns exactly one Engine session. It never sends a
// disconnect request to another process, guesses a PID or deletes foreign VPNs.
// No deadline or second interrupt skips cleanup. A forcibly killed process cannot
// guarantee cleanup and is explicitly outside this lifecycle contract.
func runForegroundSession(ctx context.Context, e *core.Engine, out, errOut io.Writer) (code int) {
	defer func() {
		if err := e.Shutdown(context.Background()); err != nil {
			code = failure(errOut, "VPN cleanup could not be confirmed. Inspect the system VPN service before reconnecting.")
		}
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	previous := ""
	for {
		snapshot := e.Snapshot()
		if snapshot.State != previous {
			// Do not emit backend errors, profile identifiers, addresses or logs.
			if _, err := fmt.Fprintln(out, snapshot.State); err != nil {
				return failure(errOut, "Could not write connection status; cleaning up the owned session.")
			}
			previous = snapshot.State
		}
		switch snapshot.State {
		case core.Failed:
			return failure(errOut, "Connection failed or was lost. Cleanup completed; fresh authentication is required.")
		case core.CleanupFailed:
			return 1 // Deferred Shutdown emits the cleanup warning.
		case core.Disconnected:
			return 0
		}
		select {
		case <-ctx.Done():
			if _, err := fmt.Fprintln(out, "Disconnecting; waiting for verified cleanup."); err != nil {
				return 1
			}
			// Shutdown uses a fresh context: cancellation requests cleanup rather
			// than cancelling the cleanup itself.
			if err := e.Shutdown(context.Background()); err != nil {
				return 1
			}
			return outputResult(writeDisconnected(out), errOut)
		case <-ticker.C:
		}
	}
}

func writeDisconnected(out io.Writer) error {
	_, err := fmt.Fprintln(out, core.Disconnected)
	return err
}
