package main

import (
	"bytes"
	"context"
	"errors"
	"mygo-vpn/internal/core"
	"strings"
	"testing"
)

func cliChallenge() core.AuthChallenge {
	return core.AuthChallenge{SessionID: strings.Repeat("a", 32), Round: 2, Fields: []core.AuthField{
		{ID: "otp", Label: "Verification code", Kind: "password"},
		{ID: "method", Label: "Method", Kind: "select", Choices: []core.AuthChoice{{ID: "totp", Label: "Authenticator"}, {ID: "backup", Label: "Recovery"}}},
	}}
}

func TestTerminalPromptBoundsAndSelectMapping(t *testing.T) {
	ch := cliChallenge()
	ch.Title = "private-title"
	ch.Message = "private-message"
	ch.Fields[0].Label = "unsafe\x1b[2J\n\r\t\u202e\u2066" + strings.Repeat("z", 2000)
	values := [][]byte{[]byte("private-otp"), []byte("2")}
	var output bytes.Buffer
	a, err := collectTerminalAnswer(context.Background(), ch, func(context.Context) ([]byte, error) {
		value := values[0]; values = values[1:]; return value, nil
	}, func(_ context.Context, value string) error { _, err := output.WriteString(value); return err })
	defer func() { for _, v := range a.Values { clear(v) } }()
	if err != nil || string(a.Values["otp"]) != "private-otp" || string(a.Values["method"]) != "backup" || a.Round != ch.Round || a.SessionID != ch.SessionID { t.Fatal("valid answer did not preserve session or map selection") }
	for _, secret := range []string{"private-otp", "private-title", "private-message", "\x1b", "\r", "\t", "\u202e", "\u2066", strings.Repeat("z", 97)} {
		if strings.Contains(output.String(), secret) { t.Fatal("terminal text disclosed an answer or unbounded/unsafe gateway data") }
	}
	if !strings.Contains(output.String(), "Gateway field 1") { t.Fatal("missing local prompt context") }
}

func TestTerminalPromptRejectsMalformedFormBeforeInput(t *testing.T) {
	mutations := []func(*core.AuthChallenge){
		func(c *core.AuthChallenge) { c.SessionID = "not-a-session" },
		func(c *core.AuthChallenge) { c.Round = 0 },
		func(c *core.AuthChallenge) { c.Round = 9 },
		func(c *core.AuthChallenge) { c.Fields = nil },
		func(c *core.AuthChallenge) { c.Fields[1].ID = c.Fields[0].ID },
		func(c *core.AuthChallenge) { c.Fields[0].ID = "\n" },
		func(c *core.AuthChallenge) { c.Fields[0].Kind = "sso" },
		func(c *core.AuthChallenge) { c.Fields[0].Choices = []core.AuthChoice{{ID: "bad"}} },
		func(c *core.AuthChallenge) { c.Fields[1].Choices = nil },
		func(c *core.AuthChallenge) { c.Fields[1].Choices[1].ID = "totp" },
		func(c *core.AuthChallenge) { c.Fields[0].Label = strings.Repeat("x", 2049) },
		func(c *core.AuthChallenge) { c.Fields[0].Label = string([]byte{0xff}) },
	}
	for _, mutate := range mutations {
		ch := cliChallenge(); mutate(&ch)
		_, err := collectTerminalAnswer(context.Background(), ch,
			func(context.Context) ([]byte, error) { t.Fatal("read before complete validation"); return nil, nil },
			func(context.Context, string) error { t.Fatal("displayed malformed form"); return nil })
		if err == nil { t.Fatal("malformed form accepted") }
	}
}

func TestTerminalPromptFailureClearsPartialAnswers(t *testing.T) {
	for _, second := range [][]byte{[]byte("0"), []byte("33"), []byte("-1"), []byte("1x"), []byte(""), []byte("001"), []byte("\n"), {0xff}, bytes.Repeat([]byte{'x'}, 4097)} {
		first := []byte("private-otp")
		reads := 0
		a, err := collectTerminalAnswer(context.Background(), cliChallenge(), func(context.Context) ([]byte, error) {
			reads++; if reads == 1 { return first, nil }; return second, nil
		}, func(context.Context, string) error { return nil })
		if err == nil || len(a.Values) != 0 || bytes.Count(first, []byte{0}) != len(first) || bytes.Count(second, []byte{0}) != len(second) { t.Fatal("failure retained partial answer") }
	}
}

func TestTerminalPromptOutputFailureClearsAnswers(t *testing.T) {
	secret := []byte("private-otp")
	read := false
	_, err := collectTerminalAnswer(context.Background(), cliChallenge(), func(context.Context) ([]byte, error) { read = true; return secret, nil }, func(context.Context, string) error {
		if read { return errors.New("untrusted-output-error") }; return nil
	})
	if err == nil || err.Error() != errTerminalAuth.Error() || bytes.Count(secret, []byte{0}) != len(secret) { t.Fatal("output failure retained answer or exposed error") }
}

func TestTerminalPromptCancellationClearsAnswers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	secret := []byte("private-otp")
	_, err := collectTerminalAnswer(ctx, cliChallenge(), func(context.Context) ([]byte, error) { cancel(); return secret, nil }, func(context.Context, string) error { return nil })
	if err == nil || bytes.Count(secret, []byte{0}) != len(secret) { t.Fatal("cancellation retained answer") }
}

func TestTerminalAnswerLimit(t *testing.T) {
	if !validTerminalAnswer(bytes.Repeat([]byte{'x'}, 4096)) || validTerminalAnswer(bytes.Repeat([]byte{'x'}, 4097)) || validTerminalAnswer([]byte("secret\n")) { t.Fatal("terminal answer bounds incorrect") }
}
