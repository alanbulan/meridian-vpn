package desktop

import (
	"context"
	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/core"
)

type authRequest struct {
	ctx       context.Context
	challenge core.AuthChallenge
	answer    chan core.AuthAnswer
}

func (a *App) configureAuth(adapter core.Adapter) {
	if capable, ok := adapter.(interface{ SetAuthPrompt(core.AuthPrompt) }); ok {
		capable.SetAuthPrompt(a.requestAuth)
	}
}

// Only channels cross the authentication worker/UI boundary. All widgets and
// their strings are owned by the main thread; cancellation never accesses them.
func (a *App) requestAuth(ctx context.Context, challenge core.AuthChallenge) (core.AuthAnswer, error) {
	request := &authRequest{ctx: ctx, challenge: challenge, answer: make(chan core.AuthAnswer)}
	select {
	case a.authRequests <- request:
	case <-ctx.Done():
		return core.AuthAnswer{}, ctx.Err()
	}
	select {
	case answer := <-request.answer:
		return answer, nil
	case <-ctx.Done():
		return core.AuthAnswer{}, ctx.Err()
	}
}
func (a *App) pollAuth() {
	if a.authCurrent != nil && a.authCurrent.ctx.Err() != nil {
		a.authCurrent = nil
		a.authValues = nil
	}
	if a.authCurrent != nil {
		return
	}
	select {
	case request := <-a.authRequests:
		if request.ctx.Err() != nil || a.ShuttingDown {
			return
		}
		a.authCurrent = request
		a.authValues = make(map[string]string)
		for _, field := range request.challenge.Fields {
			if field.Kind == "select" && len(field.Choices) > 0 {
				a.authValues[field.ID] = field.Choices[0].ID
			}
		}
	default:
	}
}
func (a *App) authForm(c *ui.Context) {
	request := a.authCurrent
	ui.Text(c, a.tr("Gateway authentication")).FontSize(18).Bold()
	// Server-provided labels are inert text, never links, commands or markup.
	if request.challenge.Title != "" {
		ui.Text(c, request.challenge.Title).FillWidth().FontSize(13)
	}
	if request.challenge.Message != "" {
		ui.Text(c, request.challenge.Message).FillWidth().FontSize(12)
	}
	for _, field := range request.challenge.Fields {
		f := field
		ui.Text(c, f.Label).FontSize(12).FillWidth()
		value := a.authValues[f.ID]
		switch f.Kind {
		case "select":
			if len(f.Choices) == 0 {
				continue
			}
			labels := make([]string, len(f.Choices))
			index := 0
			for i, choice := range f.Choices {
				labels[i] = choice.Label + " [" + choice.ID + "]"
				if choice.ID == value {
					index = i
				}
			}
			selected := labels[index]
			ui.Select(c.Key("auth-"+f.ID), &selected, labels).FillWidth()
			for _, choice := range f.Choices {
				if choice.Label+" ["+choice.ID+"]" == selected {
					value = choice.ID
					break
				}
			}
		case "password":
			ui.TextInput(c.Key("auth-"+f.ID), &value).Password().FillWidth()
		default:
			ui.TextInput(c.Key("auth-"+f.ID), &value).FillWidth()
		}
		a.authValues[f.ID] = value
	}
	ui.Row(c).Gap(10).Children(func() {
		if ui.PrimaryButton(c.Key("submit-auth"), a.tr("Continue authentication")).Clicked() {
			a.submitAuth()
		}
		if ui.Button(c.Key("cancel-auth"), a.tr("Cancel")).Clicked() {
			a.authValues = nil
			a.authCurrent = nil
			_ = a.Engine.Disconnect()
		}
	})
}
func (a *App) submitAuth() {
	request := a.authCurrent
	if request == nil {
		return
	}
	answer := core.AuthAnswer{SessionID: request.challenge.SessionID, Round: request.challenge.Round, Values: make(map[string][]byte)}
	for k, v := range a.authValues {
		answer.Values[k] = []byte(v)
	}
	select {
	case request.answer <- answer:
		a.authCurrent = nil
		a.authValues = nil
	default:
		for _, value := range answer.Values {
			clear(value)
		}
		if request.ctx.Err() != nil {
			a.authCurrent = nil
			a.authValues = nil
		}
	}
}
