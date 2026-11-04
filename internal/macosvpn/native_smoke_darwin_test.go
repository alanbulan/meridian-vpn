//go:build darwin

package macosvpn

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ebitengine/purego"
)

// Explicit opt-in only. This checks real function bindings without starting,
// stopping, creating, editing or enumerating any system network service.
func TestMacOSReadOnlyABI(t *testing.T) {
	if os.Getenv("MERIDIAN_MACOS_ABI_TEST") != "1" {
		t.Skip("未启用 macOS 原生只读 ABI 验证")
	}
	a, err := loadAPI()
	if err != nil || a == nil {
		t.Fatal("无法加载 Apple 系统框架")
	}
	for _, value := range []string{"Meridian只读ABI", "PPP", "L2TP", "vpn.example.invalid"} {
		ref := a.createString(0, value, utf8Encoding)
		if ref == 0 {
			t.Fatal("CoreFoundation 字符串分配失败")
		}
		func() {
			defer a.release(ref)
			if a.typeID(ref) != a.stringTypeID() || a.stringLength(ref) <= 0 {
				t.Fatal("CoreFoundation 字符串类型或长度 ABI 不匹配")
			}
			if value == "Meridian只读ABI" {
				if a.stringValue(ref) != "" {
					t.Fatal("诊断字段的 ASCII 限制失效")
				}
			} else if a.stringValue(ref) != value {
				t.Fatal("CoreFoundation 字符串读取 ABI 不匹配")
			}
		}()
	}
	cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		t.Fatal("无法打开数值 ABI 验证所需的系统框架")
	}
	defer func() {
		if purego.Dlclose(cf) != nil {
			t.Error("系统框架验证引用释放失败")
		}
	}()
	var createBytes func(uintptr, *byte, int, uint32, uint8) uintptr
	purego.RegisterLibFunc(&createBytes, cf, "CFStringCreateWithBytes")
	raw := []byte("PAP\x00suffix")
	ref := createBytes(0, &raw[0], len(raw), utf8Encoding, 0)
	if ref == 0 {
		t.Fatal("内嵌 NUL 边界字符串分配失败")
	}
	func() {
		defer a.release(ref)
		if a.stringLength(ref) != len(raw) || a.stringValue(ref) != "" {
			t.Fatal("真实 CF 字符串的内嵌 NUL 拒绝检查未通过")
		}
	}()
	var createNumber func(uintptr, int, *int64) uintptr
	purego.RegisterLibFunc(&createNumber, cf, "CFNumberCreate")
	for _, expected := range []int64{1, 2147483648, 1<<62 - 1} {
		ref := createNumber(0, 4, &expected)
		if ref == 0 {
			t.Fatal("CoreFoundation 数值分配失败")
		}
		func() {
			defer a.release(ref)
			var actual int64
			if a.typeID(ref) != a.numberTypeID() || a.numberIsFloatType(ref) != 0 || a.numberGetValue(ref, 4, &actual) == 0 || actual != expected {
				t.Fatal("CoreFoundation 64 位整数 ABI 不匹配")
			}
		}()
	}
	name := a.createString(0, "Meridian read-only ABI probe", utf8Encoding)
	if name == 0 {
		t.Fatal("只读配置引用名称分配失败")
	}
	defer a.release(name)
	prefs := a.preferencesCreate(0, name, 0)
	if prefs == 0 {
		t.Fatal("SystemConfiguration 只读配置引用创建失败")
	}
	defer a.release(prefs)
	if a.typeID(prefs) == 0 {
		t.Fatal("SystemConfiguration 配置引用类型无效")
	}
	t.Log("已验证真实 CF 字符串、64 位整数及只读配置引用；未验证 VPN 连接、路由、DNS、签名或授权")
}

// This separate test requires an explicitly selected service. It never starts
// or stops it. Reports only coarse status/counts; no IDs, gateways or raw data.
func TestMacOSExistingServicePreflight(t *testing.T) {
	id := os.Getenv("MERIDIAN_MACOS_SERVICE_ID")
	if os.Getenv("MERIDIAN_MACOS_ABI_TEST") != "1" || id == "" {
		t.Skip("未明确选择待检查的 macOS 系统服务")
	}
	if !validServiceID(id) {
		t.Fatal("系统服务标识无效")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	observed, err := InspectExistingService(ctx, id)
	if err != nil {
		t.Fatal("所选服务的只读预检未通过；未建立或断开连接")
	}
	if observed.Configuration.ServiceID != id || (observed.Status != Disconnected && observed.Status != Connected) {
		t.Fatal("所选服务的身份或状态不匹配")
	}
	if observed.Status == Connected && observed.Generation == nil {
		t.Fatal("活动服务缺少会话观测信息")
	}
	state := "未连接"
	if observed.Status == Connected {
		state = "系统报告已连接，尚未验收隧道"
	}
	t.Logf("只读预检通过，状态：%s；未输出服务标识、网关、账号或凭据", state)
}
