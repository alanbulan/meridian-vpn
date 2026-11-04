# 第三方源码与分发范围

本仓库是 Meridian 的开发源码检查点，不是签名发行版，也不是完整的 VPN 分发包。根 Go 模块在 `go.mod` / `go.sum` 中固定了 MyGo 和间接依赖的 Go 模块版本。请保留 `docs/third-party` 中的许可声明、`docs/MYGO-LICENSE.txt` 中的 MyGo 声明，以及 `internal/desktop/assets/lucide` 下的 Lucide 许可证。

实验性原生源码树在 `integration/univpn-native` 下保留 OpenConnect 上游源码归档、版本元数据、补丁系列和许可证文件。重新分发经过修改的原生组件时，请保留对应源码和许可声明。带日期的发布说明及可复现的纯声明补丁见 [OpenConnect 修改说明](integration/univpn-native/native/openconnect/MODIFICATIONS.md)。外围的 MIT 声明不会改变 OpenConnect 或其依赖的许可证。在未来分发任何二进制前，应审查该二进制及其实际链接方式对应的义务。

`integration/univpn-native/licenses/THIRD_PARTY_NOTICES.md` 是继承自上游的材料，描述了范围更广的 Python 管理器和打包系统。该声明提及 PyInstaller、PyGObject、WebKit、PyObjC 或 Windows Wintun 包，不代表 Meridian 包含或已经构建这些组件。Meridian 界面使用 MyGo；本检查点不提供 Python 桌面管理器或 Wintun 驱动。Linux 系统后端使用的 OpenConnect/NetworkManager 属于外部系统依赖。

原始检查点没有为 Meridian 自有代码提供覆盖整个仓库的许可授权。公开仓库本身不等于选择许可证。维护者必须另行决定该许可；无论如何选择，第三方条款仍然适用。

CI 制品仅包含新构建的 Meridian Go 图形界面和命令行程序，不包含实验性原生工作进程、根文件系统、系统 VPN 插件、签名凭据或安装程序。这些是开发构建，不是已通过 VPN 验收的发行版。
