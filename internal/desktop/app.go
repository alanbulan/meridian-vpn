package desktop

import (
	"fmt"
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/autostart"
	"mygo-vpn/internal/buildinfo"
	"mygo-vpn/internal/core"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type adapterCheck struct {
	adapter core.Adapter
	auth    core.Capability
}

// sessionTarget retains only the explicitly selected endpoint, never credentials.
// It is process-local and bound to the engine attempt that accepted the form.
type sessionTarget struct {
	attemptID uint64
	profileID string
	gateway   string
}

type App struct {
	windowsActiveProfile      *core.Profile
	windowsActiveAttemptID    uint64
	WindowsBorrowedEnabled    bool
	WindowsPersistenceConsent bool
	WindowsSharedConsent      bool
	CleanupRetrying           bool
	macService                macServiceUI
	Startup                   *autostart.Manager
	StartupStatus             autostart.Status
	StartupError              string
	StartupConfirm            bool
	StartupBusy               bool
	observedConnected         bool
	reauthAt                  time.Time
	reauthProfileID           string
	reauthAttemptID           uint64
	reauthVisible             bool
	sessionTarget             sessionTarget
	AuthCapability            core.Capability
	Store                     core.Store
	Config                    core.Config
	Engine                    *core.Engine
	Window                    *mygo.Window
	Page                      string
	Draft                     core.Profile
	Editing                   bool
	Notice                    string
	DeleteID                  string
	TrayAvailable             bool
	LoadBlocked               bool
	Capability                core.Capability
	Adapter                   core.Adapter
	Password                  string
	KeyPassword               string
	IPsecPSK                  string
	GatewayChoice             string
	AdditionalGatewaysText    string
	SwitchID                  string
	SwitchPending             bool
	Authorized                bool
	ProxyConsent              bool
	ConnectPanel              bool
	Search                    string
	ConnectedAt               time.Time
	ShuttingDown              bool
	Checking                  bool
	recheckResults            chan adapterCheck
	FileBusy                  bool
	AdvancedOpen              bool
	MTUText                   string
	MRUText                   string
	editorGeneration          uint64
	SystemLanguage            string
	authRequests              chan *authRequest
	authCurrent               *authRequest
	authValues                map[string]string
}

func New(path string) *App { return NewWithAdapter(path, defaultAdapter()) }
func NewWithAdapter(path string, adapter core.Adapter) *App {
	a := &App{authRequests: make(chan *authRequest, 1), Store: core.Store{Path: path}, Page: "Overview", Adapter: adapter, Engine: core.NewEngine(adapter)}
	var err error
	a.initializeStartup()
	a.configureAuth(adapter)
	a.Config, err = a.Store.Load()
	a.Capability = a.Adapter.Capability()
	a.AuthCapability = core.NewMFAHelper().Capability()
	if err != nil {
		a.LoadBlocked = true
		a.Notice = "Could not load configuration. Existing file will not be overwritten automatically."
	}
	return a
}
func (a *App) commit(cfg core.Config) bool {
	if a.LoadBlocked {
		a.Notice = "Configuration is invalid. Back it up and restart with a different --config path."
		return false
	}
	if err := a.Store.Save(cfg); err != nil {
		a.Notice = "Could not save configuration: " + err.Error()
		return false
	}
	a.Config = cfg
	a.Notice = ""
	return true
}
func (a *App) setTray(enabled bool) {
	cfg := a.copyConfig()
	cfg.Settings.MinimizeToTray = enabled
	a.commit(cfg)
}
func (a *App) navigate(page string) {
	a.macService.reset()
	if a.authCurrent != nil {
		a.authCurrent = nil
		a.authValues = nil
		_ = a.Engine.Disconnect()
	}
	a.Page = page
	a.Editing = false
	a.DeleteID = ""
	a.Notice = ""
	a.clearCredentials()
}
func (a *App) clearCredentials() {
	a.Password = ""
	a.KeyPassword = ""
	a.IPsecPSK = ""
	a.GatewayChoice = ""
	a.Authorized = false
	a.ProxyConsent = false
	a.WindowsPersistenceConsent = false
	a.WindowsSharedConsent = false
	a.ConnectPanel = false
}
func (a *App) BeginShutdown() {
	a.macService.reset()
	a.clearReauthentication()
	a.ShuttingDown = true
	a.authCurrent = nil
	a.authValues = nil
	a.clearCredentials()
	a.SwitchID = ""
	a.SwitchPending = false
}
func (a *App) canConnect(p *core.Profile) bool {
	state := a.Engine.Snapshot().State
	return p != nil && (!p.InteractiveAuth || a.AuthCapability.Available) && !a.LoadBlocked && !a.ShuttingDown && !a.Checking && a.Capability.Available && a.supportsProtocol(p.Protocol) && (state == core.Disconnected || state == core.Failed)
}
func (a *App) beginRecheck(factory func() core.Adapter) {
	if a.Checking || a.ShuttingDown || a.busy() || a.Engine.Snapshot().State == core.CleanupFailed {
		return
	}
	a.Checking = true
	a.recheckResults = make(chan adapterCheck, 1)
	out := a.recheckResults
	go func() { out <- adapterCheck{adapter: factory(), auth: core.NewMFAHelper().Capability()} }()
}
func (a *App) pollRecheck() {
	if !a.Checking {
		return
	}
	select {
	case result := <-a.recheckResults:
		adapter := result.adapter
		a.Checking = false
		if a.ShuttingDown {
			return
		}
		if err := a.Engine.ReplaceAdapter(adapter); err != nil {
			a.Notice = err.Error()
			return
		}
		a.configureAuth(adapter)
		a.Adapter = adapter
		a.Capability = adapter.Capability()
		a.AuthCapability = result.auth
	default:
	}
}

func (a *App) copyConfig() core.Config {
	cfg := a.Config
	cfg.Profiles = append([]core.Profile(nil), cfg.Profiles...)
	for i := range cfg.Profiles {
		if cfg.Profiles[i].SystemService != nil {
			options := *cfg.Profiles[i].SystemService
			options.Targets = append([]string(nil), options.Targets...)
			cfg.Profiles[i].SystemService = &options
		}
		if cfg.Profiles[i].WindowsBorrowed != nil {
			options := *cfg.Profiles[i].WindowsBorrowed
			cfg.Profiles[i].WindowsBorrowed = &options
		}
		if cfg.Profiles[i].L2TP != nil {
			options := *cfg.Profiles[i].L2TP
			cfg.Profiles[i].L2TP = &options
		}
		cfg.Profiles[i].AdditionalGateways = append([]string(nil), cfg.Profiles[i].AdditionalGateways...)
	}
	return cfg
}
func (a *App) selected() *core.Profile {
	for i := range a.Config.Profiles {
		if a.Config.Profiles[i].ID == a.Config.SelectedID {
			return &a.Config.Profiles[i]
		}
	}
	return nil
}
func (a *App) startEdit(p *core.Profile) {
	a.editorGeneration++
	a.AdvancedOpen = false
	a.clearCredentials()
	a.Draft = core.Profile{Protocol: "anyconnect"}
	if a.WindowsBorrowedEnabled {
		a.Draft.Protocol = core.WindowsBorrowedProtocol
		a.Draft.WindowsBorrowed = &core.WindowsBorrowedOptions{}
	}
	if p != nil {
		a.Draft = *p
		if p.SystemService != nil {
			options := *p.SystemService
			options.Targets = append([]string(nil), options.Targets...)
			a.Draft.SystemService = &options
		}
		if p.WindowsBorrowed != nil {
			options := *p.WindowsBorrowed
			a.Draft.WindowsBorrowed = &options
		}
		if p.L2TP != nil {
			options := *p.L2TP
			a.Draft.L2TP = &options
		}
	}
	a.AdditionalGatewaysText = strings.Join(a.Draft.AdditionalGateways, " ")
	a.MRUText = ""
	if a.Draft.L2TP != nil && a.Draft.L2TP.MRU != 0 {
		a.MRUText = strconv.Itoa(a.Draft.L2TP.MRU)
	}
	a.MTUText = ""
	if a.Draft.MTU != 0 {
		a.MTUText = strconv.Itoa(a.Draft.MTU)
	}
	a.Editing = true
	a.Page = "Profiles"
	a.Notice = ""
}
func (a *App) saveDraft() {
	if a.LoadBlocked {
		a.Notice = "Configuration is invalid. Saving is blocked to preserve the existing file."
		return
	}
	a.Draft.AdditionalGateways = nil
	for _, gateway := range strings.Fields(a.AdditionalGatewaysText) {
		a.Draft.AdditionalGateways = append(a.Draft.AdditionalGateways, gateway)
	}
	a.Draft.MTU = 0
	if strings.TrimSpace(a.MTUText) != "" {
		value, err := strconv.Atoi(strings.TrimSpace(a.MTUText))
		if err != nil {
			a.Notice = "MTU must be a whole number"
			return
		}
		a.Draft.MTU = value
	}
	if a.Draft.Protocol == "l2tp" && a.Draft.L2TP != nil {
		a.Draft.L2TP.MRU = 0
		if strings.TrimSpace(a.MRUText) != "" {
			value, err := strconv.Atoi(strings.TrimSpace(a.MRUText))
			if err != nil {
				a.Notice = a.tr("MRU must be a whole number")
				return
			}
			a.Draft.L2TP.MRU = value
		}
	}
	if a.Draft.CAFile != "" {
		if err := core.ValidateCAFile(a.Draft.CAFile); err != nil {
			a.Notice = err.Error()
			return
		}
	}
	if err := core.ValidateClientCertificate(a.Draft); err != nil {
		a.Notice = err.Error()
		return
	}
	if a.Draft.Protocol == "univpn" {
		if _, err := core.UniVPNArgs(a.Draft); err != nil {
			a.Notice = err.Error()
			return
		}
	}
	if err := core.ValidateProfile(a.Draft); err != nil {
		a.Notice = err.Error()
		return
	}
	cfg := a.copyConfig()
	p := a.Draft
	p.AllowProxySystemAuth = false
	if p.ID == "" {
		p.ID = core.NewID()
	}
	if err := cfg.Upsert(p); err != nil {
		a.Notice = err.Error()
		return
	}
	cfg.SelectedID = p.ID
	if a.commit(cfg) {
		a.Editing = false
	}
}
func (a *App) applyTheme(c *ui.Context) {
	t := ui.LightTheme()
	t.Background = ui.Hex("#f7f8fa")
	t.Surface = ui.Hex("#ffffff")
	t.SurfaceHover = ui.Hex("#eef2f6")
	t.SurfacePressed = ui.Hex("#e5ebf2")
	t.Text = ui.Hex("#202936")
	t.TextMuted = ui.Hex("#87919e")
	t.Border = ui.Hex("#e6eaf0")
	t.Accent = ui.Hex("#267aee")
	t.AccentHover = ui.Hex("#1765d0")
	t.AccentPressed = ui.Hex("#1356b5")
	t.AccentText = ui.Hex("#ffffff")
	if a.Config.Settings.DarkMode {
		t = ui.DarkTheme()
		t.Background = ui.Hex("#15191f")
		t.Surface = ui.Hex("#1d232c")
		t.SurfaceHover = ui.Hex("#2a323e")
		t.SurfacePressed = ui.Hex("#343e4c")
		t.Text = ui.Hex("#e9edf3")
		t.TextMuted = ui.Hex("#8994a4")
		t.Border = ui.Hex("#303844")
		t.Accent = ui.Hex("#65a2ff")
		t.AccentText = ui.Hex("#111a28")
	}
	t.Radius = 9
	t.FontSize = 14
	c.SetTheme(t)
}
func (a *App) soft() ui.Color {
	if a.Config.Settings.DarkMode {
		return ui.Hex("#243448")
	}
	return ui.Hex("#eaf2fe")
}
func (a *App) sidebar() ui.Color {
	if a.Config.Settings.DarkMode {
		return ui.Hex("#191e25")
	}
	return ui.Hex("#f0f2f5")
}
func (a *App) busy() bool {
	s := a.Engine.Snapshot().State
	return s == core.Connecting || s == core.Connected || s == core.Disconnecting
}
func (a *App) switchTheme(dark bool) {
	cfg := a.copyConfig()
	cfg.Settings.DarkMode = dark
	a.commit(cfg)
}
func (a *App) themePicker(c *ui.Context) {
	ui.Row(c).Gap(3).Padding(3).Background(a.sidebar()).Radius(10).Children(func() {
		for _, item := range []struct {
			dark         bool
			key, caption string
		}{{false, "sun", "Light appearance"}, {true, "moon", "Dark appearance"}} {
			i := item
			b := iconButton(c, i.key, a.tr(i.caption), icons[i.key])
			if a.Config.Settings.DarkMode == i.dark {
				b.Background(c.Theme().Surface).TextColor(c.Theme().Accent)
			} else {
				b.TextColor(c.Theme().TextMuted)
			}
			if b.Clicked() {
				a.switchTheme(i.dark)
			}
		}
	})
}
func (a *App) View(c *ui.Context) {
	_, viewportHeight := c.Size()
	bodyHeight := max(float32(0), viewportHeight-70)
	paneHeight := max(float32(0), bodyHeight-20)
	a.pollMacService()
	a.pollRecheck()
	a.pollSwitch()
	a.pollAuth()
	a.pollReauthentication(time.Now())
	a.applyTheme(c)
	t := c.Theme()
	if a.busy() {
		c.After(time.Second)
	}
	if !a.reauthAt.IsZero() {
		c.After(time.Second)
	}
	if a.Checking {
		c.After(100 * time.Millisecond)
	}
	ui.Column(c).Fill().Background(t.Background).Children(func() {
		ui.Row(c).FillWidth().Height(70).Shrink(0).Padding(18, 24).Gap(12).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, icons["brand"]).Size(26, 26).TextColor(t.Accent)
			ui.Text(c, "Meridian").FontSize(19).Bold()
			ui.Text(c, a.tr("VPN connection")).FontSize(13).TextColor(t.TextMuted)
			ui.Spacer(c)
			if a.Page != "Overview" || a.ConnectPanel || a.Editing {
				if iconButton(c, "back", a.tr("Back to connections"), icons["back"]).Clicked() {
					a.navigate("Overview")
				}
			}
			if iconButton(c, "settings", a.tr("Settings"), icons["Settings"]).Clicked() {
				a.navigate("Settings")
			}
			a.themePicker(c)
		})
		ui.Row(c).FillWidth().Height(bodyHeight).MinHeight(0).MaxHeight(bodyHeight).Shrink(0).Padding(0, 20, 20).Gap(0).AlignItems(ui.Stretch).Children(func() {
			a.connectionStatus(c)
			ui.Column(c).Grow(1).Basis(0).Height(paneHeight).MinHeight(0).MaxHeight(paneHeight).Padding(24).Gap(18).Background(t.Surface).Border(1, t.Border).Radius(0, 16, 16, 0).Children(func() {
				if a.Notice != "" {
					ui.Text(c, a.tr(a.Notice)).FillWidth().Padding(10).FontSize(12).Background(a.soft()).Radius(8)
				}
				ui.Scroll(c).Fill().MinHeight(0).Children(func() {
					ui.Column(c).FillWidth().Gap(18).Children(func() {
						if a.authCurrent != nil {
							a.authForm(c)
						} else if a.ConnectPanel {
							a.connectForm(c)
						} else if a.Editing {
							a.editor(c)
						} else {
							switch a.Page {
							case "MacSystemService":
								a.macSystemServiceForm(c)
							case "Settings":
								a.settings(c)
							case "Activity":
								a.activity(c)
							case "Support":
								a.support(c)
							default:
								a.connectionList(c)
							}
						}
					})
				})
			})
		})
	})
	if a.Checking {
		c.After(100 * time.Millisecond)
	} else if a.busy() {
		c.After(time.Second)
	}
}
func (a *App) stat(c *ui.Context, title, value string) {
	ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
		ui.Text(c, a.tr(title)).FontSize(12).TextColor(c.Theme().TextMuted).Width(104)
		ui.Text(c, value).FontSize(13).Grow(1)
	})
}
func (a *App) connectionStatus(c *ui.Context) {
	_, viewportHeight := c.Size()
	paneHeight := max(float32(0), viewportHeight-90)
	t := c.Theme()
	p := a.selected()
	snapshot := a.Engine.Snapshot()
	state := snapshot.State
	if a.macServiceOwnsAttempt(snapshot) {
		p = a.macService.activeProfile
	} else if a.windowsOwnsAttempt(snapshot) && snapshot.State != core.Failed {
		p = a.windowsActiveProfile
	}
	ui.Column(c).Width(294).Height(paneHeight).MinHeight(0).MaxHeight(paneHeight).Shrink(0).Padding(20, 22).Gap(12).Background(a.sidebar()).Border(1, t.Border).Radius(16, 0, 0, 16).Children(func() {
		ui.Row(c).FillWidth().Gap(12).AlignItems(ui.Center).Padding(2, 2, 10).Children(func() {
			ui.Column(c).Gap(7).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, icons["computer"]).Size(35, 35).TextColor(t.TextMuted)

			})
			ui.Column(c).Grow(1).Gap(7).AlignItems(ui.Center).Children(func() {
				statusIcon := "closed"
				if state == core.Connected {
					statusIcon = "check"
				}
				ui.Icon(c, icons[statusIcon]).Size(16, 16).TextColor(t.TextMuted)
				ui.Icon(c, icons["arrows"]).Size(28, 28).TextColor(t.TextMuted)
				ui.Text(c, a.tr(state)).FontSize(10).TextColor(t.TextMuted)
			})
			ui.Column(c).Gap(7).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, icons["vpn"]).Size(35, 35).TextColor(t.Accent)

			})
		})
		name, user := "—", "—"
		if p != nil {
			name = p.Name
			if p.Username != "" {
				user = p.Username
			}
		}
		a.stat(c, "VPN name", name)
		up, down, virtualIP := "—", "—", "—"
		if snapshot.MetricsAvailable {
			up = formatBytes(snapshot.Uploaded)
			down = formatBytes(snapshot.Downloaded)
			if snapshot.VirtualIP != "" {
				virtualIP = snapshot.VirtualIP
			}
		}
		a.stat(c, "Uploaded", up)
		a.stat(c, "Downloaded", down)
		duration := "—"
		if state == core.Connected && !snapshot.ConnectedAt.IsZero() {
			d := int(time.Since(snapshot.ConnectedAt).Seconds())
			duration = fmt.Sprintf("%02d:%02d:%02d", d/3600, d/60%60, d%60)
		}
		a.stat(c, "Connection duration", duration)
		ui.Box(c).FillWidth().Height(1).Background(t.Border)
		a.stat(c, "Username", user)
		a.stat(c, "Virtual IP", virtualIP)
		auth := "—"
		if state == core.Connected {
			auth = a.tr("Authenticated")
		}
		a.stat(c, "Authentication", auth)
		ui.Spacer(c)
		if a.macServiceOwnsAttempt(snapshot) {
			ui.Text(c, "有限验证：系统服务与指定目标路由；不保证全应用 DNS/IPv6 防泄漏。").FontSize(11).FillWidth()
		}
		if a.windowsOwnsAttempt(snapshot) {
			ui.Text(c, "Limited Windows verification: observed interface only; no full route/DNS leak protection.").FontSize(11).FillWidth().Wrap()
		}
		if !a.Capability.Available || p != nil && p.InteractiveAuth && !a.AuthCapability.Available || p != nil && !a.supportsProtocol(p.Protocol) || state == core.CleanupFailed || state == core.Failed {
			ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, icons["info"]).Size(13, 13).TextColor(t.TextMuted)
				ui.Text(c, a.tr("Setup needed")).FontSize(11).TextColor(t.TextMuted)
				ui.Spacer(c)
				if ui.ButtonBase(c.Key("diagnostics")).Label(a.tr("View details")).Padding(3).TextColor(t.Accent).Children(func() { ui.Text(c, a.tr("View details")).FontSize(11) }).Clicked() {
					a.navigate("Settings")
				}
			})
		}
		if a.busy() {
			if ui.Button(c.Key("disconnect"), a.tr("Disconnect")).FillWidth().Height(42).Disabled(state == core.Disconnecting).Clicked() {
				_ = a.Engine.Disconnect()
			}
		} else if a.macServiceOwnsAttempt(snapshot) {
			if ui.PrimaryButton(c.Key("mac-recheck-connect"), "重新检查系统服务").FillWidth().Height(42).Disabled(a.ShuttingDown || state == core.CleanupFailed).Clicked() {
				a.navigate("MacSystemService")
			}
		} else {
			disabled := !a.canConnect(p)
			b := ui.PrimaryButton(c.Key("connect"), a.tr("Connect")).Label(a.tr("Connect to this gateway")).FillWidth().Height(42).Disabled(disabled)
			if disabled {
				b.Background(t.Background).TextColor(t.TextMuted).Border(1, t.Border)
			}
			if b.Clicked() {
				a.openConnectForm()
			}
		}
	})
}
func (a *App) connectionList(c *ui.Context) {
	a.reauthenticationNotice(c)
	t := c.Theme()
	ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
		ui.Text(c, a.tr("Choose connection")).FontSize(15).Bold()
		ui.Spacer(c)
		proxy := ui.ButtonBase(c.Key("proxy")).Label(a.tr("Proxy settings")).Tooltip(a.tr("Configure proxy for the selected connection")).Padding(8).Disabled(a.selected() == nil || a.busy()).Children(func() {
			ui.Row(c).Gap(5).Children(func() { ui.Icon(c, icons["proxy"]).Size(15, 15); ui.Text(c, a.tr("Proxy settings")).FontSize(12) })
		})
		if proxy.Clicked() {
			a.startEdit(a.selected())
			a.AdvancedOpen = true
		}
		if iconButton(c, "import", a.tr("Import profiles"), icons["import"]).Disabled(a.FileBusy || a.busy()).Clicked() {
			a.chooseImport()
		}
		if ui.ButtonBase(c.Key("add-profile")).Label(a.tr("+  Add profile")).TextColor(t.Accent).Padding(8).Disabled(a.busy()).Children(func() {
			ui.Row(c).Gap(5).Children(func() { ui.Icon(c, icons["plus"]).Size(16, 16); ui.Text(c, a.tr("New connection")).FontSize(12) })
		}).Clicked() {
			a.startEdit(nil)
		}
	})
	ui.Row(c).FillWidth().Padding(10, 12).Gap(8).AlignItems(ui.Center).Background(t.Background).Border(1, t.Border).Radius(9).Children(func() {
		ui.Icon(c, icons["search"]).Size(16, 16).TextColor(t.TextMuted)
		ui.TextInput(c.Key("search"), &a.Search).Placeholder(a.tr("Search connections")).Grow(1).Border(0, t.Border).Background(t.Background)
	})
	count := 0
	for _, profile := range a.Config.Profiles {
		q := profile
		if !strings.Contains(strings.ToLower(q.Name+" "+q.Gateway), strings.ToLower(a.Search)) {
			continue
		}
		count++
		selected := q.ID == a.Config.SelectedID
		bg := t.Background
		if selected {
			bg = a.soft()
		}
		ui.Column(c.Key(q.ID)).FillWidth().Padding(12).Gap(10).Background(bg).Radius(10).Children(func() {
			ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, icons["Profiles"]).Size(20, 20).TextColor(t.Accent)
				if ui.ButtonBase(c.Key("select")).Label(q.Name).Tooltip(q.Description).Grow(1).Disabled(a.busy()).Children(func() {
					ui.Column(c).FillWidth().Gap(5).Children(func() {
						ui.Text(c, q.Name).FontSize(13).Bold()
						ui.Text(c, gatewayHost(q.Gateway)).FontSize(11).TextColor(t.TextMuted)
					})
				}).Clicked() {
					cfg := a.copyConfig()
					cfg.SelectedID = q.ID
					a.commit(cfg)
				}
				if a.Engine.Snapshot().State == core.Connected && !selected && !a.macServiceOwnsAttempt(a.Engine.Snapshot()) && !a.windowsOwnsAttempt(a.Engine.Snapshot()) {
					if iconButton(c, "switch", a.tr("Switch connection"), icons["refresh"]).Disabled(a.SwitchPending).Clicked() {
						a.SwitchID = q.ID
					}
				}
				if iconButton(c, "edit", a.tr("Edit"), icons["edit"]).Disabled(a.busy()).Clicked() {
					a.startEdit(&q)
				}
				if iconButton(c, "delete", a.tr("Delete"), icons["trash"]).Disabled(a.busy()).Clicked() {
					a.DeleteID = q.ID
				}
				if iconButton(c, "export", a.tr("Export profiles"), icons["export"]).Disabled(a.FileBusy).Clicked() {
					a.chooseExport(&q)
				}
			})
			if a.SwitchID == q.ID && !a.SwitchPending {
				ui.Text(c, a.tr("Disconnect current VPN, then sign in again?")).FontSize(12)
				ui.Row(c).Gap(8).Children(func() {
					if ui.Button(c, a.tr("Cancel")).Clicked() {
						a.SwitchID = ""
					}
					if ui.Button(c, a.tr("Confirm switch")).Clicked() {
						a.beginSwitch(q.ID)
					}
				})
			}
			if a.DeleteID == q.ID {
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					ui.Text(c, a.tr("Delete this profile permanently?")).FontSize(12).Grow(1)
					if ui.Button(c, a.tr("Cancel")).Clicked() {
						a.DeleteID = ""
					}
					if ui.Button(c, a.tr("Confirm delete")).TextColor(t.Danger).Clicked() {
						cfg := a.copyConfig()
						cfg.Delete(q.ID)
						if a.commit(cfg) {
							a.DeleteID = ""
						}
					}
				})
			}
		})
	}
	if count == 0 {
		ui.Column(c).FillWidth().Padding(28).Gap(12).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, icons["Profiles"]).Size(30, 30).TextColor(t.TextMuted)
			text := "No connections yet"
			if len(a.Config.Profiles) > 0 {
				text = "No matching connections"
			}
			ui.Text(c, a.tr(text)).FontSize(13).TextColor(t.TextMuted)
		})
	}
}
func gatewayHost(s string) string {
	u, e := url.Parse(s)
	if e == nil && u.Host != "" {
		return u.Host
	}
	return s
}
func (a *App) editor(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).FillWidth().Padding(24).Gap(13).Background(t.Surface).Border(1, t.Border).Radius(14).Children(func() {
		ui.Text(c, a.tr("Connection profile")).FontSize(18).Bold()
		a.label(c, "Name")
		ui.TextInput(c.Key("profile-name"), &a.Draft.Name).Placeholder(a.tr("Work network")).FillWidth()
		a.label(c, "Description")
		ui.TextInput(c.Key("description"), &a.Draft.Description).Placeholder(a.tr("Optional")).FillWidth()
		a.label(c, "Gateway")
		gatewayPlaceholder := "https://vpn.example.com"
		if a.Draft.Protocol == "l2tp" || a.Draft.Protocol == core.WindowsBorrowedProtocol {
			gatewayPlaceholder = "vpn.example.com"
		}
		ui.TextInput(c.Key("profile-gateway"), &a.Draft.Gateway).Placeholder(gatewayPlaceholder).FillWidth()
		a.label(c, "Protocol")
		protocol := a.Draft.Protocol
		ui.Select(c.Key("profile-protocol"), &protocol, a.profileProtocols()).FillWidth()
		if protocol != a.Draft.Protocol {
			a.setDraftProtocol(protocol)
		}
		usernameLabel, usernamePlaceholder := "Username", "Optional"
		if a.Draft.Protocol == core.WindowsBorrowedProtocol {
			usernameLabel, usernamePlaceholder = "Username (required)", "Required"
		}
		a.label(c, usernameLabel)
		ui.TextInput(c.Key("profile-user"), &a.Draft.Username).Placeholder(a.tr(usernamePlaceholder)).FillWidth()
		if ui.ButtonBase(c.Key("advanced")).Label(a.tr("Authentication & transport")).Padding(4).TextColor(t.Accent).Children(func() {
			ui.Row(c).Gap(7).Children(func() {
				ui.Icon(c, icons["Settings"]).Size(15, 15)
				ui.Text(c, a.tr("Authentication & transport")).FontSize(12)
			})
		}).Clicked() {
			a.AdvancedOpen = !a.AdvancedOpen
		}
		if a.Draft.Protocol == core.WindowsBorrowedProtocol {
			a.windowsBorrowedFields(c)
		}
		if a.AdvancedOpen && a.Draft.Protocol == "l2tp" {
			a.l2tpFields(c)
		}
		if a.AdvancedOpen && a.Draft.Protocol == "univpn" {
			a.univpnFields(c)
		}
		if a.AdvancedOpen && a.Draft.Protocol != "l2tp" && a.Draft.Protocol != "univpn" && a.Draft.Protocol != core.WindowsBorrowedProtocol {
			a.label(c, "Additional gateways (up to 15, separated by spaces)")
			ui.TextInput(c.Key("additional-gateways"), &a.AdditionalGatewaysText).FillWidth()
			a.clientCertificateFields(c)
			ui.Checkbox(c.Key("interactive-auth"), &a.Draft.InteractiveAuth, a.tr("Interactive authentication (MFA helper)"))
			if a.Draft.InteractiveAuth && !a.AuthCapability.Available {
				a.label(c, "Interactive authentication helper is not installed")
			}
			a.label(c, "Authentication group")
			ui.TextInput(c.Key("auth-group"), &a.Draft.AuthGroup).FillWidth()
			a.label(c, "Custom CA certificate")
			ui.Row(c).FillWidth().Gap(8).Children(func() {
				ui.TextInput(c.Key("ca-file"), &a.Draft.CAFile).Grow(1)
				if iconButton(c, "choose-ca", a.tr("Choose CA certificate"), icons["import"]).Disabled(a.FileBusy).Clicked() {
					a.chooseCA()
				}
			})
			a.label(c, "Proxy URL (HTTP / SOCKS5)")
			ui.TextInput(c.Key("proxy-url"), &a.Draft.ProxyURL).Placeholder("http://127.0.0.1:8080").FillWidth()
			a.label(c, "No embedded credentials; HTTP may use system authentication")
			ui.Checkbox(c.Key("disable-udp"), &a.Draft.DisableUDP, a.tr("Use TCP only (disable UDP/DTLS)"))
			a.label(c, "MTU (blank = automatic)")
			ui.TextInput(c.Key("mtu"), &a.MTUText).Placeholder(a.tr("Automatic")).FillWidth()
		}
		ui.Box(c).Height(6)
		ui.Row(c).Gap(10).Children(func() {
			if ui.PrimaryButton(c.Key("save-profile"), a.tr("Save profile")).Clicked() {
				a.saveDraft()
			}
			if ui.Button(c.Key("cancel-profile"), a.tr("Cancel")).Clicked() {
				a.Editing = false
				a.Notice = ""
			}
		})
	})
}
func (a *App) activity(c *ui.Context) {
	t := c.Theme()
	ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
		a.label(c, "This session")
		ui.Spacer(c)
		if iconButton(c, "export-logs", a.tr("Export activity"), icons["export"]).Disabled(a.FileBusy).Clicked() {
			a.chooseLogExport()
		}
		if iconButton(c, "clear-logs", a.tr("Clear activity"), icons["trash"]).Clicked() {
			a.Engine.ClearLogs()
		}
	})
	ui.Column(c).FillWidth().Padding(20).Gap(18).Background(t.Surface).Border(1, t.Border).Radius(14).Children(func() {
		for _, l := range a.Engine.Snapshot().Logs {
			ui.Row(c).Gap(16).Children(func() {
				ui.Text(c, l.Time.Format("15:04:05")).FontSize(12).TextColor(t.TextMuted)
				ui.Text(c, a.tr(l.Message)).FontSize(13).Grow(1)
			})
		}
	})
}
func (a *App) settings(c *ui.Context) {
	a.macServiceSettingsEntry(c)
	a.startupSettings(c)
	t := c.Theme()
	ui.Column(c).FillWidth().Padding(22).Gap(20).Background(t.Surface).Border(1, t.Border).Radius(14).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() { ui.Text(c, a.tr("Appearance")).Grow(1); a.themePicker(c) })
		ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
			ui.Text(c, a.tr("LANGUAGE")).Grow(1)
			lang := "中文"
			if a.Config.Settings.Language == "en" {
				lang = "English"
			} else if a.Config.Settings.Language == "system" {
				lang = a.tr("Follow system")
			}
			before := lang
			ui.Select(c.Key("language"), &lang, []string{"中文", "English", a.tr("Follow system")}).Width(160)
			if lang != before {
				cfg := a.copyConfig()
				cfg.Settings.Language = "zh"
				if lang == "English" {
					cfg.Settings.Language = "en"
				} else if lang == a.tr("Follow system") {
					cfg.Settings.Language = "system"
				}
				a.commit(cfg)
			}
		})
		recovery := a.Config.Settings.ReauthOnLoss
		ui.Checkbox(c.Key("reauth-on-loss"), &recovery, a.tr("Offer fresh authentication after connection loss"))
		if recovery != a.Config.Settings.ReauthOnLoss {
			cfg := a.copyConfig()
			cfg.Settings.ReauthOnLoss = recovery
			if a.commit(cfg) && !recovery {
				a.clearReauthentication()
			}
		}
		old := a.Config.Settings.MinimizeToTray
		enabled := old
		ui.Checkbox(c, &enabled, a.tr("Keep in tray when the window closes")).Disabled(!a.TrayAvailable)
		if old != enabled {
			a.setTray(enabled)
		}
	})
	ui.Column(c).FillWidth().Padding(22).Gap(14).Background(t.Surface).Border(1, t.Border).Radius(14).Children(func() {
		ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, icons["info"]).Size(18, 18).TextColor(t.Accent)
			ui.Text(c, a.tr("Diagnostics")).Bold().Grow(1)
			if iconButton(c, "check-backend", a.tr("Recheck prerequisites"), icons["refresh"]).Disabled(a.busy() || a.Checking || a.ShuttingDown || a.Engine.Snapshot().State == core.CleanupFailed).Clicked() {
				a.beginRecheck(a.platformAdapter)
			}
		})
		ui.Text(c, a.tr(a.Capability.Message)).FillWidth().FontSize(13)
		if p := a.selected(); p != nil && p.InteractiveAuth && !a.AuthCapability.Available {
			a.label(c, "Interactive authentication helper is not installed")
		}
		if a.WindowsBorrowedEnabled {
			a.label(c, "Existing Windows VPN · experimental limited mode")
		} else if a.macServiceOwnsAttempt(a.Engine.Snapshot()) {
			a.label(c, "macOS system service · limited target-route verification")
		} else {
			a.label(c, "Linux · AnyConnect / L2TP-IPsec · NetworkManager")
		}
		a.label(c, "Experimental UniVPN requires a separately configured trusted broker")
		a.label(c, "UniVPN compatibility is not established; ask IT for the gateway and protocol.")
		if a.Engine.Snapshot().State == core.CleanupFailed && (a.windowsOwnsAttempt(a.Engine.Snapshot()) || a.macServiceOwnsAttempt(a.Engine.Snapshot())) {
			if ui.Button(c.Key("retry-scoped-cleanup"), "Retry cleanup verification").Disabled(a.CleanupRetrying).Clicked() {
				a.retryScopedCleanup()
			}
		}
		if a.Engine.Snapshot().State == core.CleanupFailed || a.Engine.Snapshot().State == core.Failed {
			ui.Text(c, a.tr(a.Engine.Snapshot().Message)).TextColor(t.Danger).FillWidth()
		}
	})
	ui.Row(c).Gap(8).Children(func() {
		if ui.Button(c, a.tr("Inspect INI (read only)")).Disabled(a.FileBusy).Clicked() {
			a.chooseINIPreview()
		}
		if ui.Button(c, a.tr("Import profiles")).Disabled(a.FileBusy || a.busy()).Clicked() {
			a.chooseImport()
		}
		if ui.Button(c, a.tr("Export profiles")).Disabled(a.FileBusy).Clicked() {
			a.chooseExport(nil)
		}
	})
	if ui.Button(c, a.tr("Activity")).Clicked() {
		a.Page = "Activity"
	}
	if ui.Button(c, a.tr("Export diagnostics")).Disabled(a.FileBusy || a.ShuttingDown).Clicked() {
		a.chooseDiagnosticsExport()
	}
	if ui.Button(c, a.tr("Capabilities & reference fields")).Clicked() {
		a.Page = "Support"
	}
	a.label(c, fmt.Sprintf(a.tr("Meridian %s / MyGo 0.7.4 / pure Go native UI"), buildinfo.Version))
}
func (a *App) connectForm(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).FillWidth().Padding(22).Gap(14).Background(t.Surface).Border(1, t.Border).Radius(14).Children(func() {
		ui.Text(c, a.tr("Session authentication")).FontSize(16).Bold()
		if selected := a.selected(); selected != nil {
			choices := append([]string{selected.Gateway}, selected.AdditionalGateways...)
			a.label(c, "Gateway for this session")
			ui.Text(c, a.GatewayChoice).FillWidth()
			if len(choices) > 1 {
				gateway := a.GatewayChoice
				ui.Select(c.Key("session-gateway"), &gateway, choices).FillWidth()
				a.selectSessionGateway(gateway)
			}
			if selected.Protocol == "l2tp" {
				a.label(c, "IPsec pre-shared key (this session only)")
				ui.TextInput(c.Key("ipsec-psk"), &a.IPsecPSK).Password().FillWidth()
			}
			if selected.ClientCertificate != "" {
				a.label(c, "Certificate passphrase / token PIN (if required)")
				ui.TextInput(c.Key("key-password"), &a.KeyPassword).Password().FillWidth()
			}
		}
		a.label(c, "Session password")
		ui.TextInput(c.Key("session-password"), &a.Password).Password().FillWidth()
		ui.Checkbox(c.Key("authorize-network"), &a.Authorized, a.tr("Authorize network changes"))
		p := a.selected()
		if p != nil && p.Protocol == core.WindowsBorrowedProtocol {
			a.windowsBorrowedConsent(c)
		}
		needsProxyConsent := p != nil && p.ProxyURL != ""
		if needsProxyConsent {
			ui.Checkbox(c.Key("proxy-consent"), &a.ProxyConsent, a.tr("Allow proxy to use system authentication for this connection"))
		}
		ui.Row(c).Gap(10).Children(func() {
			if ui.PrimaryButton(c.Key("confirm-connect"), a.tr("Connect")).Disabled(!a.Authorized || !a.canConnect(a.selected()) || needsProxyConsent && !a.ProxyConsent || !a.windowsConsentReady(p)).Clicked() {
				a.submitConnection()
			}
			if ui.Button(c.Key("cancel-connect"), a.tr("Cancel")).Clicked() {
				a.clearCredentials()
			}
		})
	})
}

func formatBytes(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	v := float64(n) / 1024
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}
