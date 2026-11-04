# Lucide 官方图标

这些 SVG 文件**逐字节复制，未经任何修改**，来源于
[Lucide 官方仓库](https://github.com/lucide-icons/lucide)的
[`0.468.0`](https://github.com/lucide-icons/lucide/tree/0.468.0/icons) 标签。

- 源代码归档：https://github.com/lucide-icons/lucide/archive/refs/tags/0.468.0.tar.gz
- 归档 SHA-256：`91cda05023eae90e2cb8a52c0b1abedd5ebad1bdbbadcde76f01aab652828691`
- 上游源文件路径：`icons/<filename>.svg`
- 各文件的 SHA-256 哈希：[`SHA256SUMS`](SHA256SUMS)
- 许可证：原样复制的上游 [`LICENSE`](LICENSE)（ISC，含 Feather 署名）

应用使用 Go `embed.FS` 嵌入这些静态资源，通过 MyGo 的 `ui.MustParseSVG` 解析一次，
并使用 MyGo 原生的 `ui.Icon` 显示。
不使用 Web 运行时、JavaScript 软件包、网络获取、自定义 SVG 路径或 SVG 重写。
参见 MyGo 的[图标文档](https://mygo.egoist.dev/docs/ui/icon)。

`internal/desktop/icons.go` 将应用内名称映射到官方文件名。
品牌标记使用 Lucide 的 `waypoints`，不是自行绘制的标志。
拓扑箭头使用官方的正方形 `arrow-left-right` 资源。
正方形资源应在正方形边界内渲染；如果沿用旧自定义箭头的 82 × 12 边界，
该图标会显得很小（MyGo 会等比适配 SVG，不会拉伸）。

更新时，从另一个官方且锁定版本的 Lucide 发布中复制选定 SVG 和许可证，不修改这些文件；
更新本文的来源记录及哈希清单，然后运行图标测试。
`TestLucideAssetIntegrity` 会检查每个哈希。

## 系统托盘位图

`tray-network.png` 由未修改的官方 `network.svg` 栅格化生成，尺寸为 32 × 32，
背景透明，并采用应用的淡紫色。托盘 API 要求使用 PNG。
没有手绘的像素或几何形状。原始 SVG 保持不变；渲染器通过独立的样式表接收显示颜色。
转换使用已安装的 librsvg 2.60.0 和 Cairo 1.18.4：

```sh
python3 internal/desktop/assets/lucide/generate_tray.py
```

脚本使用 Python 标准库的 `ctypes` 加载系统库。
它仅用于复现生成过程；应用嵌入最终的 PNG，显示时不需要 Python 或 librsvg。
即使渲染出的像素一致，不同渲染器版本的 PNG 输出也可能不同。

PNG SHA-256：`7ad25b7a6e244d9ace9b1fac22c404ff3680a9bacde170c8b7d81b2fe7da3fdb`
