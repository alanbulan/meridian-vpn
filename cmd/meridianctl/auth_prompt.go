package main

import (
	"context"
	"errors"
	"fmt"
	"mygo-vpn/internal/core"
	"unicode"
	"unicode/utf8"
)

// This is deliberately separate from stdin/stdout/stderr. Gateway text and
// credential responses must never become redirected command output or logs.
type authTerminal interface {
	Prompt(context.Context, core.AuthChallenge) (core.AuthAnswer, error)
	Close() error
}

var errTerminalAuth = errors.New("terminal authentication unavailable or canceled")

const maxTerminalAnswer = 4096

func validTerminalChallenge(ch core.AuthChallenge) bool {
	if len(ch.SessionID) != 32 || ch.Round < 1 || ch.Round > 8 || len(ch.Fields) < 1 || len(ch.Fields) > 16 || len(ch.Title) > 2048 || len(ch.Message) > 4096 {
		return false
	}
	for _, c := range ch.SessionID {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') { return false }
	}
	seen := make(map[string]bool)
	for _, f := range ch.Fields {
		if !validAuthID(f.ID) || seen[f.ID] || len(f.Label) > 2048 || !utf8.ValidString(f.Label) { return false }
		seen[f.ID] = true
		switch f.Kind {
		case "text", "password":
			if len(f.Choices) != 0 { return false }
		case "select":
			if len(f.Choices) < 1 || len(f.Choices) > 32 { return false }
		default:
			return false
		}
		choices := make(map[string]bool)
		for _, c := range f.Choices {
			if !validAuthID(c.ID) || choices[c.ID] || len(c.Label) > 2048 || !utf8.ValidString(c.Label) { return false }
			choices[c.ID] = true
		}
	}
	return true
}

func validAuthID(id string) bool {
	if len(id) < 1 || len(id) > 128 || !utf8.ValidString(id) { return false }
	for _, r := range id { if unicode.IsControl(r) { return false } }
	return true
}

// Gateway labels are data, never terminal commands. Omit free-form title and
// message, strip controls/formatting, quote labels, and cap every displayed label.
func terminalLabel(label string) string {
	runes := make([]rune, 0, 96)
	for _, r := range label {
		if len(runes) == 96 { break }
		if unicode.IsPrint(r) && !unicode.Is(unicode.Cf, r) { runes = append(runes, r) } else { runes = append(runes, ' ') }
	}
	return string(runes)
}

func collectTerminalAnswer(ctx context.Context, ch core.AuthChallenge, read func(context.Context) ([]byte, error), write func(context.Context, string) error) (answer core.AuthAnswer, err error) {
	if !validTerminalChallenge(ch) || ctx.Err() != nil { return answer, errTerminalAuth }
	answer = core.AuthAnswer{SessionID: ch.SessionID, Round: ch.Round, Values: make(map[string][]byte)}
	defer func() {
		if err != nil {
			for _, value := range answer.Values { clear(value) }
			answer = core.AuthAnswer{}
		}
	}()
	if err = write(ctx, "\nGateway authentication. All answers are hidden. Ctrl+C cancels.\n"); err != nil { return answer, errTerminalAuth }
	for i, field := range ch.Fields {
		if err = write(ctx, fmt.Sprintf("Gateway field %d, label %q\n", i+1, terminalLabel(field.Label))); err != nil { return answer, errTerminalAuth }
		for j, choice := range field.Choices {
			if err = write(ctx, fmt.Sprintf("  %d: %q\n", j+1, terminalLabel(choice.Label))); err != nil { return answer, errTerminalAuth }
		}
		prompt := "Hidden answer: "
		if field.Kind == "select" { prompt = "Choice number (hidden): " }
		if err = write(ctx, prompt); err != nil { return answer, errTerminalAuth }
		value, readErr := read(ctx)
		if readErr != nil || ctx.Err() != nil || !validTerminalAnswer(value) {
			clear(value)
			return answer, errTerminalAuth
		}
		if field.Kind == "select" {
			// Parse directly from bytes, without retaining secret input strings.
			selected := 0
			if len(value) > 0 && len(value) <= 2 {
				for _, b := range value {
					if b < '0' || b > '9' { selected = -1; break }
					selected = selected*10 + int(b-'0')
				}
			}
			clear(value)
			if selected < 1 || selected > len(field.Choices) { return answer, errTerminalAuth }
			value = []byte(field.Choices[selected-1].ID)
		}
		answer.Values[field.ID] = value
		if err = write(ctx, "\n"); err != nil { return answer, errTerminalAuth }
	}
	if ctx.Err() != nil { return answer, errTerminalAuth }
	return answer, nil // The existing helper bridge now owns and clears Values.
}

func validTerminalAnswer(value []byte) bool {
	if len(value) > maxTerminalAnswer || !utf8.Valid(value) { return false }
	for len(value) != 0 {
		r, n := utf8.DecodeRune(value)
		if unicode.IsControl(r) { return false }
		value = value[n:]
	}
	return true
}
