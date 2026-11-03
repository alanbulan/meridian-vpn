//go:build meridian_uifixture

package desktop

import (
	"context"
	"github.com/egoist/mygo"
	"mygo-vpn/internal/core"
)

// AuthenticationPreview is compiled only into an explicitly labeled UI fixture.
// It has no working adapter and never authenticates or marks a tunnel connected.
func AuthenticationPreview(path string) *App {
	a := NewWithAdapter(path, previewAdapter{})
	ctx, cancel := context.WithCancel(context.Background())
	mygo.App.OnBeforeQuit(func(_ *mygo.QuitEvent) { cancel() })
	a.Notice = "认证界面测试 · 不联网 · 不建立 VPN"
	a.authCurrent = &authRequest{ctx: ctx, challenge: core.AuthChallenge{SessionID: "ui-preview-only", Round: 2, Title: "示例网关 · 身份验证", Message: "请输入测试验证码，或取消。此界面不会发送任何信息。", Fields: []core.AuthField{{ID: "otp", Label: "动态验证码", Kind: "password"}, {ID: "group", Label: "访问组", Kind: "select", Choices: []core.AuthChoice{{ID: "staff", Label: "员工"}, {ID: "contractor", Label: "合作伙伴"}}}}}, answer: make(chan core.AuthAnswer)}
	a.authValues = map[string]string{"group": "staff"}
	request := a.authCurrent
	go func() {
		select {
		case answer := <-request.answer:
			for _, value := range answer.Values {
				clear(value)
			}
			mygo.RunOnMain(func() {
				a.Notice = "测试输入已清除 · 未发送任何信息"
				if a.Window != nil {
					a.Window.Invalidate()
				}
			})
		case <-ctx.Done():
		}
	}()
	return a
}

type previewAdapter struct{}

func (previewAdapter) Capability() core.Capability {
	return core.Capability{Message: "UI fixture only; network disabled"}
}
func (previewAdapter) Start(context.Context, core.Profile, []byte) (core.Session, error) {
	panic("UI fixture must never connect")
}
