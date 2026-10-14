# 24.10 适配 C2000MAX 老周版本

给 **NRadio C2000MAX** 路由器定制的 `luci-app-homeproxy`，版本 **1.0.0-r30**。

目标系统是 ImmortalWrt 24.10（`aarch64_cortex-a53`，firewall4 / nftables）。
这是从 r23 的 ipk 反推、按这套固件的实际行为逐条改出来的可用版本，不是简单重新打包。

---

## 这个包解决了什么

原包 r23 装在这台设备上基本用不了。按严重程度排：

| 症状 | 原因 |
| --- | --- |
| 装完启动没反应，sing-box 起不来 | 启动阶段要联网下载分流规则集，而那个 CDN 在国内被 RST，sing-box 直接退出，procd 反复重试成崩溃循环 |
| 国外站点全部超时，国内正常 | sing-box 去连 dnsmasq 返回的污染地址；`sniff_override` 必须开着才能用 TLS 握手还原真实域名 |
| 规则被反复清空 | 固件的 eqos 服务在每次接口事件时清空整条 mangle PREROUTING 链 |
| 客户端 DNS 一直转圈 | 固件的 `dns_redirect` 与 TPROXY 抢同一个 53 端口，回复对不上 conntrack |
| 页面顶部两条标签栏 | 主题 argon 自己画了一条，包又画了一条 |
| 节点页面折叠、测速、排序全是死的 | 选择器找的是 `fieldset`，而这套固件的 CBI 模板渲染的是 `div` |
| 卸载任一包就把引擎一起删了 | r23 自带一份 sing-box 二进制并声明 `Replaces: sing-box`，两个包同时拥有同一个文件 |

完整的逐版本记录（r23 → r30，每条都写了症状、根因、修法、验证方式）在
[`build/README.md`](build/README.md)。

## 仓库内容

```
.
├── luci-app-homeproxy_1.0.0-r30_aarch64_cortex-a53.ipk   可直接安装的包
└── build/
    ├── README.md      逐版本改动记录与验证过程（详细）
    ├── ctl/           opkg 控制文件（control / postinst / prerm / conffiles）
    ├── data/          打包进 ipk 的文件树
    ├── gen.lua        在设备上跑的配置生成器端到端测试
    ├── mkipk.py       打包脚本
    └── test/          回归测试，含一套 headless Chrome 页面测试
```

## 安装

sing-box 二进制需要另行安装，本包只依赖它、不再自带一份：

```sh
opkg update
opkg install sing-box
opkg install luci-app-homeproxy_1.0.0-r30_aarch64_cortex-a53.ipk
```

装完在 LuCI 的 **服务 → HomeProxy** 里配置。`/etc/config/homeproxy` 默认
`enabled '0'`，不会自己启动。

> 从 r26 或更早升级，需要先手动杀掉正在运行的 guard：
> `kill $(cat /var/run/homeproxy/guard.pid)`。r27 之前的版本占着 procd 的服务锁，
> 不先杀掉的话 prerm 会卡死。

## 重新打包

```sh
python3 build/mkipk.py build/data build/ctl luci-app-homeproxy_1.0.0-r30_aarch64_cortex-a53.ipk
```

容器格式是 `gzip(tar(./debian-binary, ./data.tar.gz, ./control.tar.gz))`，
**不是** Debian 的 `ar` 归档——这台设备的 opkg 只认前者，喂 `ar` 会直接报
`Failed to extract control file`。注意 `file` 命令对两种格式都报
"Debian binary package"，判断要用 `gunzip -c pkg.ipk | tar -tf -`。

## 测试

```sh
sh  build/test/test-firewall-guard.sh      # 防火墙规则守护
sh  build/test/test-r28-behaviour.sh       # r28 的八项行为回归
lua build/test/test-confgen.lua            # 配置生成器（需在设备上跑）
```

页面 JavaScript 的测试方式是：把设备上的 `/www/luci-static` 整棵拉到本地起镜像，
给 `/ubus` 和 action 接口套桩，再用 headless Chrome 真正渲染、真正点按钮。
说明见 [`build/test/browser/README.md`](build/test/browser/README.md)。
读代码证明不了这些脚本是对的——这部分必须在浏览器里跑过才算数。

## 上游与许可

基于上游 homeproxy（ImmortalWrt 24.10 一代）改写，前端从 JS 客户端 +
ucode 改成 luci-compat 的 Lua 分发器，只需要 sing-box 二进制。

License: GPL-2.0，与上游一致。
