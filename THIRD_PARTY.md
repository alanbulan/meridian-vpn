# Third-party source and distribution scope

This repository is a Meridian development-source checkpoint, not a signed release
or a complete VPN distribution. Its root Go module pins MyGo and indirect Go
modules in `go.mod` / `go.sum`. Preserve their notices in `docs/third-party`, the
MyGo notice in `docs/MYGO-LICENSE.txt`, and Lucide's license under
`internal/desktop/assets/lucide`.

The experimental native tree retains the OpenConnect upstream source archive,
revision metadata, patch series, and license files under
`integration/univpn-native`. Preserve corresponding source and notices when
redistributing modified native components. Dated publication notices and the
reproducible notice-only patch are described in
[integration/univpn-native/native/openconnect/MODIFICATIONS.md](integration/univpn-native/native/openconnect/MODIFICATIONS.md).
A surrounding MIT notice does not
relicense OpenConnect or its dependencies. Review the obligations for the exact
binary and linkage before any future binary release.

`integration/univpn-native/licenses/THIRD_PARTY_NOTICES.md` is inherited upstream
material describing a broader Python manager and packaging system. References in
that inherited notice to PyInstaller, PyGObject, WebKit, PyObjC or Windows Wintun
bundles are not a claim that Meridian includes or has built those packages. The
Meridian interface uses MyGo; no Python desktop manager or Wintun driver is
provided by this checkpoint. OpenConnect/NetworkManager used by the Linux system
backend are external system dependencies.

There is no repository-wide license grant for Meridian-authored code in the
original checkpoint. Publishing the repository does not by itself choose a
license. The maintainer must choose that license separately; third-party terms
remain applicable regardless of that choice.

The CI artifacts contain only the freshly built Meridian Go GUI and CLI. They do
not contain the experimental native worker, rootfs, system VPN plugins, signing
credentials, or an installer. They are development builds, not validated VPN
releases.

The separate opt-in Linux candidate workflow additionally packages the exact git
source snapshot and preserved dependency notices. When selected, it also includes
the dynamically linked authentication-only C helper, not libopenconnect or other
system libraries. This does not select a license for Meridian-authored code or
remove the maintainer's distribution review. See docs/LINUX-RELEASE.md.
