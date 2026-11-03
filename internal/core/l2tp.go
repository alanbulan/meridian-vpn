package core

// L2TP is delegated to the distribution's NetworkManager-l2tp plugin. No PPP,
// IPsec commands, configuration files or privileged service are run by Meridian.
// Property contract: https://github.com/nm-l2tp/NetworkManager-l2tp/blob/main/shared/nm-service-defines.h
import (
	"bytes"
	"context"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// L2TPOptions intentionally contains no PSK/password and requires IPsec.
// Empty PPPAuth selects MSCHAPv2. Empty proposals use the administrator's plugin
// defaults; supplying a proposal does not guarantee gateway interoperability.
type L2TPOptions struct {
	PPPAuth            string `json:"ppp_auth,omitempty"`
	Domain             string `json:"domain,omitempty"`
	RemoteID           string `json:"remote_id,omitempty"`
	IKE                string `json:"ike,omitempty"`
	ESP                string `json:"esp,omitempty"`
	ForceEncapsulation bool   `json:"force_encapsulation,omitempty"`
	MRU                int    `json:"mru,omitempty"`
}

var proposalPattern = regexp.MustCompile(`^[A-Za-z0-9_+!-]{1,256}$`)

func validateL2TPProfile(p Profile) error {
	if p.ClientCertificate != "" || p.ClientKey != "" || p.CertificateFormat != "" || p.CAFile != "" || p.ProxyURL != "" || p.DisableUDP || p.InteractiveAuth || p.AuthGroup != "" {
		return errors.New("L2TP does not support OpenConnect certificate, proxy or authentication options")
	}
	if len(p.Username) > 256 || !utf8.ValidString(p.Username) || hasControl(p.Username) || strings.ContainsAny(p.Username, ",\\=\"") {
		return errors.New("invalid L2TP username")
	}
	host := p.Gateway
	if len(host) == 0 || len(host) > 253 {
		return errors.New("L2TP gateway must be a hostname or IP address without scheme or port")
	}
	if net.ParseIP(host) == nil {
		for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return errors.New("invalid L2TP hostname")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return errors.New("invalid L2TP hostname")
				}
			}
		}
	}
	if p.L2TP == nil {
		return nil
	}
	o := p.L2TP
	switch o.PPPAuth {
	case "", "pap", "chap", "mschapv2":
	default:
		return errors.New("PPP authentication must be pap, chap or mschapv2")
	}
	for _, v := range []string{o.Domain, o.RemoteID} {
		if len(v) > 256 || !utf8.ValidString(v) || hasControl(v) || strings.ContainsAny(v, ",\\=\" ") {
			return errors.New("invalid L2TP domain or remote ID")
		}
	}
	for _, v := range []string{o.IKE, o.ESP} {
		if v != "" && !proposalPattern.MatchString(v) {
			return errors.New("IKE/ESP must be a single algorithm proposal without delimiters")
		}
	}
	if o.MRU != 0 && (o.MRU < 576 || o.MRU > 9000) {
		return errors.New("MRU must be automatic or 576–9000")
	}
	return nil
}
func l2tpData(p Profile, unit int) string {
	o := L2TPOptions{}
	if p.L2TP != nil {
		o = *p.L2TP
	}
	method := o.PPPAuth
	if method == "" {
		method = "mschapv2"
	}
	data := []string{"gateway=" + p.Gateway, "user=" + p.Username, "user-auth-type=password", "machine-auth-type=psk", "ipsec-enabled=yes", "password-flags=2", "ipsec-psk-flags=2", "refuse-eap=yes", "refuse-mschap=yes", "unit=" + strconv.Itoa(unit)}
	for _, m := range []string{"pap", "chap", "mschapv2"} {
		value := "yes"
		if method == m {
			value = "no"
		}
		data = append(data, "refuse-"+m+"="+value)
	}
	for _, kv := range [][2]string{{"domain", o.Domain}, {"ipsec-remote-id", o.RemoteID}, {"ipsec-ike", o.IKE}, {"ipsec-esp", o.ESP}} {
		if kv[1] != "" {
			data = append(data, kv[0]+"="+kv[1])
		}
	}
	if o.ForceEncapsulation {
		data = append(data, "ipsec-forceencaps=yes")
	}
	if o.MRU != 0 {
		data = append(data, "mru="+strconv.Itoa(o.MRU))
	}
	if p.MTU != 0 {
		data = append(data, "mtu="+strconv.Itoa(p.MTU))
	}
	return strings.Join(data, ",")
}
func (n *NetworkManager) startL2TP(ctx context.Context, p Profile, c Credentials) (Session, error) {
	if !n.l2tpAvailable {
		return nil, errors.New("NetworkManager-l2tp plugin is unavailable")
	}
	if p.Username == "" {
		return nil, errors.New("L2TP requires a username")
	}
	id := NewID()
	uuid := id[:8] + "-" + id[8:12] + "-4" + id[13:16] + "-a" + id[17:20] + "-" + id[20:]
	// Request an unused PPP unit. pppd may fall back after a race, so readiness
	// additionally compares the UUID's assigned address with this interface.
	raw, _ := strconv.ParseUint(id[:4], 16, 16)
	unit := 1000 + int(raw)%60000
	iface := "ppp" + strconv.Itoa(unit)
	if !n.interfaceGone(iface) {
		return nil, errors.New("PPP interface is already in use; retry")
	}
	op, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	s := &nmSession{verifyAddress: true, n: n, uuid: uuid, iface: iface, ready: make(chan error, 1), done: make(chan error, 1)}
	s.ctx, s.cancel = context.WithCancel(ctx)
	fail := func(err error) (Session, error) {
		if cleanup := s.Stop(); cleanup != nil {
			return nil, errors.Join(err, cleanup)
		}
		return nil, err
	}
	args := []string{"--wait", "15", "connection", "add", "save", "no", "type", "vpn", "con-name", "Meridian-" + id[:8], "connection.uuid", uuid, "connection.autoconnect", "no", "vpn.service-type", "org.freedesktop.NetworkManager.l2tp", "vpn.data", l2tpData(p, unit)}
	if _, err := n.runner.Run(op, n.nm, args, nil); err != nil {
		return fail(errors.New("NetworkManager could not create temporary L2TP profile"))
	}
	var input bytes.Buffer
	input.WriteString("vpn.secrets.password:")
	input.Write(c.Password)
	input.WriteByte('\n')
	input.WriteString("vpn.secrets.ipsec-psk:")
	input.Write(c.IPsecPSK)
	input.WriteByte('\n')
	_, err := n.runner.Run(op, n.nm, []string{"--wait", "60", "connection", "up", "uuid", uuid, "passwd-file", "/proc/self/fd/0"}, input.Bytes())
	clear(input.Bytes())
	if err != nil {
		return fail(errors.New("L2TP/IPsec activation failed"))
	}
	if !s.verified(op) {
		return fail(errors.New("NetworkManager did not verify the L2TP tunnel"))
	}
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}
	s.updateMetrics()
	s.ready <- nil
	go s.monitor()
	return s, nil
}

func interfaceHasAddress(name, cidr string) bool {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil {
		return false
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addresses {
		a, n, e := net.ParseCIDR(addr.String())
		if e == nil && a.Equal(ip) && bytes.Equal(n.Mask, network.Mask) {
			return true
		}
	}
	return false
}
