// Meridian is a native Go desktop VPN client. NetworkManager owns privileged networking.
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"log"
	"mygo-vpn/internal/buildinfo"
	"mygo-vpn/internal/desktop"
	"os"
	"path/filepath"
	"time"
)

func main() {
	// Version queries never open a window or read user configuration.
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("Meridian %s (%s)\n", buildinfo.Version, buildinfo.Commit)
		return
	}
	base, err := os.UserConfigDir()
	if err != nil {
		log.Fatal(err)
	}
	config := flag.String("config", filepath.Join(base, "meridian", "profiles.json"), "Local configuration file (never contains credentials)")
	flag.Parse()
	a := desktop.New(*config)
	quitting, quitReady := false, false
	requestQuit := func() {}
	requestQuit = func() {
		if a.StartupBusy {
			a.Notice = "启动项正在保存，请稍后再退出。"
			if a.Window != nil {
				a.Window.Show()
				a.Window.Invalidate()
			}
			return
		}
		if quitting {
			return
		}
		quitting = true
		a.BeginShutdown()
		engine := a.Engine
		if a.Window != nil {
			a.Window.Invalidate()
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err := engine.Shutdown(ctx)
			mygo.RunOnMain(func() {
				quitting = false
				if err != nil {
					a.ShuttingDown = false
					a.Notice = "VPN 清理未完成，请先检查 NetworkManager，应用将保持打开。"
					if a.Window != nil {
						a.Window.Show()
						a.Window.Invalidate()
					}
					return
				}
				quitReady = true
				mygo.App.Quit()
			})
		}()
	}
	mygo.App.OnBeforeQuit(func(e *mygo.QuitEvent) {
		if !quitReady {
			e.PreventDefault()
			requestQuit()
		}
	})
	mygo.App.WhenReady(func() {
		a.SetSystemLanguages(mygo.App.PreferredLanguages())
		a.Window = mygo.NewWindow(mygo.WindowOptions{Title: "Meridian — Private access", Width: 960, Height: 620, MinWidth: 880, MinHeight: 580, Content: ui.View(a.View)})
		tray, err := mygo.NewTray(mygo.TrayOptions{ID: "meridian", Icon: desktop.TrayIcon(), ToolTip: "Meridian", Menu: mygo.NewMenu([]*mygo.MenuItem{{Label: "打开 Meridian", Click: func(_ *mygo.MenuItem, _ *mygo.Window) { a.Window.Show(); a.Window.Focus() }}, {Label: "连接 / 查看连接", Click: func(_ *mygo.MenuItem, _ *mygo.Window) { a.OpenConnectionFromTray() }}, {Label: "断开连接", Click: func(_ *mygo.MenuItem, _ *mygo.Window) { a.DisconnectFromTray() }}, {Label: "退出 Meridian", Click: func(_ *mygo.MenuItem, _ *mygo.Window) { mygo.App.Quit() }}})})
		if err == nil {
			a.TrayAvailable = true
			tray.OnClick(func() { a.Window.Show(); a.Window.Focus() })
		}
		a.Window.OnClose(func(e *mygo.CloseEvent) {
			if quitReady {
				return
			}
			if a.TrayAvailable && a.Config.Settings.MinimizeToTray {
				e.PreventDefault()
				a.Window.Hide()
			} else {
				e.PreventDefault()
				requestQuit()
			}
		})
	})
	mygo.App.OnLocaleChanged(func(_ string) {
		a.SetSystemLanguages(mygo.App.PreferredLanguages())
		if a.Window != nil {
			a.Window.Invalidate()
		}
	})
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}
