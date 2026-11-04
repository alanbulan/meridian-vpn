package main

import (
	"bytes"
	"context"
	"errors"
	"mygo-vpn/internal/macosvpn"
	"strings"
	"testing"
)

func TestNoImplicitInspection(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"--unknown"}, {"extra"}} {
		var b bytes.Buffer
		run(args, &b, func(context.Context, string) (macosvpn.ServiceInspection, error) {
			t.Fatal("未选择服务却读取系统")
			return macosvpn.ServiceInspection{}, nil
		})
	}
}
func TestNoPrivateOutput(t *testing.T) {
	for _, failure := range []bool{false, true} {
		var b bytes.Buffer
		code := run([]string{"--service-id", "private-id"}, &b, func(_ context.Context, id string) (macosvpn.ServiceInspection, error) {
			if id != "private-id" {
				t.Fatal("标识不匹配")
			}
			if failure {
				return macosvpn.ServiceInspection{}, errors.New("private-gateway private-secret")
			}
			return macosvpn.ServiceInspection{Status: macosvpn.Disconnected, Configuration: macosvpn.ServiceConfiguration{Gateway: "private-gateway", ServiceID: id}}, nil
		})
		if failure != (code != 0) {
			t.Fatal("错误退出码")
		}
		if strings.Contains(b.String(), "private-") {
			t.Fatal("泄漏私有字段")
		}
	}
}
