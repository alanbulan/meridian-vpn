// meridian-macos-inspect only observes an explicitly selected existing service.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"mygo-vpn/internal/macosvpn"
	"os"
)

func run(args []string, out io.Writer, inspect func(context.Context, string) (macosvpn.ServiceInspection, error)) int {
	flags := flag.NewFlagSet("meridian-macos-inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	id := flags.String("service-id", "", "明确选择的现有系统服务标识")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprintln(out, "用法：meridian-macos-inspect --service-id <系统服务标识>\n只读检查；不建立、断开或修改 VPN。同步系统调用可能等待，取消不构成强制超时保证。")
			return 0
		}
		fmt.Fprintln(out, "参数无效；未检查系统服务。")
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(out, "不接受额外参数；未检查系统服务。")
		return 2
	}
	if *id == "" {
		fmt.Fprintln(out, "macOS 只读诊断工具。请用 --help 查看用法；未读取系统服务，未建立 VPN。")
		return 0
	}
	observation, err := inspect(context.Background(), *id)
	if err != nil {
		fmt.Fprintln(out, "所选服务检查未通过；未建立或断开连接。请确认 macOS 平台及明确选择的 L2TP 服务。")
		return 1
	}
	state := "未连接"
	if observation.Status == macosvpn.Connected {
		state = "系统报告已连接，尚未验收隧道"
	} else if observation.Status != macosvpn.Disconnected {
		fmt.Fprintln(out, "服务状态不稳定；不记录为通过。")
		return 1
	}
	fmt.Fprintf(out, "只读检查通过。状态：%s。\n未输出服务标识、网关、账号或凭据；不代表路由、DNS、流量或 VPN 产品已验收。\n", state)
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stdout, macosvpn.InspectExistingService)) }
