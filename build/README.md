# luci-app-homeproxy 定制版 (r30) — 构建源码

这个目录是 `../luci-app-homeproxy_1.0.0-r30_aarch64_cortex-a53.ipk` 的完整源码。
针对 NRadio C2000MAX（192.168.66.1，ImmortalWrt 24.10）改的，原包 r23 的
10 个问题在这里都修掉了。

## 目录

    data/        打进包里的所有文件（etc/ usr/ www/）
    ctl/         control 元数据、postinst、prerm、conffiles
    mkipk.py     打包脚本
    test/        回归测试，**不打进包里**
    gen.lua      配置生成器的自测脚本（在设备上跑，见下）

## 重新打包

    python3 mkipk.py data ctl ../luci-app-homeproxy_1.0.0-r30_aarch64_cortex-a53.ipk

构建是确定性的（固定 mtime、固定文件顺序），同一份源码重复打包出来的字节完全一样。

**注意封装格式**：必须是 `gzip(tar(debian-binary, data.tar.gz, control.tar.gz))`。
这台设备的 opkg 只认这种；改成 Debian 的 `ar` 格式会直接报
`pkg_init_from_file: Malformed package file` 装不上。`file` 命令对两种格式都
可能说是 "Debian binary package"，不能拿它当判断依据 —— 用

    gunzip -c x.ipk | tar -tf -

看里面是不是那三个成员。

`mkipk.py` 里有一份 `EXEC_PREFIXES`/`EXEC_SUFFIXES` 兜底：`etc/init.d/`、
`etc/hotplug.d/`、`*.sh` 一律按 0755 打包。这是有意的 —— 之前 `firewall.sh`
在构建树里是 644，装上去服务能启动、日志正常，但一条规则都不装，还不报错。

## 回归测试

    test/test-firewall-guard.sh          本机直接跑，只用 sh/grep/sleep，27 项
    test/test-confgen.lua                只能在设备上跑（本机没有 lua），5 项
    test/test-confgen-r28.lua            只能在设备上跑，14 项
    test/test-r28-behaviour.sh           只能在设备上跑，21 项
    test/browser/                        节点页 JS 的浏览器测试（见文件里的说明）

看门狗那套靠 PATH 上的假 `netstat`/`ip`/`nslookup`/`start-stop-daemon` 和假
`firewall.sh` 驱动真实的脚本，把生产环境 20 秒的中断压成 2 秒。两个关键回归：
「代理死了 20 秒必须把规则撤掉」和「重启时一两秒的端口空档不许撤」。

    scp test/test-confgen.lua root@192.168.66.1:/tmp/
    ssh root@192.168.66.1 'lua /tmp/test-confgen.lua'

后两个只针对 r28 加的东西。`test-confgen-r28.lua` 带一个反向对照：脚本会按
`HP_LUA_ROOT` 去找生成器，所以把某条修复从一份拷贝里删掉再跑，就能看见**哪几条
断言是在替这条修复说话** —— 有一条修复没被任何断言盯住，对照跑出来是全绿。实测：

    sed '/for _, reserved in ipairs/,+2d' ... > /tmp/nofix-tag/homeproxy/confgen.lua
    HP_LUA_ROOT=/tmp/nofix-tag lua /tmp/test-confgen-r28.lua     # 10 passed, 4 failed
    # FATAL decode config: duplicate outbound/endpoint tag: direct

    # interval 校验绕过去之后：
    # FATAL decode config: route.rule_set[0].update_interval: time: unknown unit " days"

`test-r28-behaviour.sh` 测的是读代码读不出来的东西 —— 某个闸门在**「sing-box
活着但端口没了」**这个具体状态下到底怎么判。它把 hook 和刷新脚本从**已安装的
文件**用 sed 生成变体（再去掉修复得到反向对照），撞在假的 `firewall.sh` 和假的
`logger` 上，不碰真实规则和真实规则集。三个负向对照的意义是：**断言两侧都跑**
—— 「端口死了不装」和「端口活着要装」必须一条过一条不过，否则那个测试对一个
永远 exit 的脚本也会通过。实测 21/21。

## r28 在设备上的验证结果

不是读代码，是在 192.168.66.1 上跑出来的：

| 验证项 | 结果 |
|---|---|
| 装包 `opkg install` | r27→r28，**2 秒**（r26 时是 4 分钟挂死） |
| `lua test-confgen.lua` | 5 passed, 0 failed |
| `lua test-confgen-r28.lua` | 14 passed, 0 failed |
| 两个反向对照 | 分别 4 failed / 3 failed，报的正是要修的错 |
| `sh test-r28-behaviour.sh` | 21 passed, 0 failed |
| fd 1000 持有者 | 0 个 |
| 装完 uptime | 未重启（btime 一直没变） |

几条值得单独记的实测：

- **闸门**：同一个世界（sing-box 在跑、端口不在听、规则已没）下，r28 的端口
  闸门一次 `firewall.sh` 都不调；把闸门换回 `pidof sing-box`，它调 `check`
  两次然后 `up` —— 规则就装在死端口前面了。端口活着时 r28 照样装，所以「不装」
  不是因为脚本死了。
- **不重启**：刷新脚本换掉三个规则集之后，sing-box 的 pid 前后都是 15522，
  uptime 只走了 0.12 秒（3122.26 → 3122.38）。这是直接证据，不是推断。
- **节流戳**：全镜像失败 → 不生成 `rule_set.stamp`，原文件 md5 不变；换一个有
  效镜像且文件真有变化 → 生成戳，文件换掉。
- **订阅锁**：四种状态全部符合 —— 没人持锁就干活并清理；活 pid 持锁就拒绝且
  不抢；死 pid 持锁就接管；**pid 文件还没写出来的那一瞬间按持锁算**（偏保守的
  那一侧）。四种情况下 uci 一个字节没动。

## r25 → r26 修掉的三个问题

1. **DNS「域名策略」下拉框是死的。** `confgen.lua` 读的是 `dns_strategy`，
   而 `/etc/config/homeproxy` 和状态页写的都是 `strategy` —— 这个选项哪儿
   都不存在，所以查表永远落空、永远退回内置默认值 `prefer_ipv4`。下拉框
   存得下、显示得对、日志正常，唯独生成的 config.json 从不跟着变。默认值
   恰好等于发货值，所以看起来一直是对的。
2. **节点名字里带空格、`#`、中文就用不了。** 控制器有两处白名单按「名字是
   安全字符」写的。`select` 那处根本不必要 —— 名字只进 JSON body，从不碰
   URL 或命令行，而带 `#` 的名字正是导入器给重名节点自动加的后缀，中文名
   更是中文界面的常态；两处都返回 400/403，表现是状态页下拉框动了、节点
   没切过去、延迟测不了。现在按「编码后应该长什么样」放行，`%2e`/`%2f`
   仍然拦（那是唯一真的能越权走出去的写法）。
3. **节点页的折叠/测速/排序从来没生效。** `node.js` 按
   `fieldset.cbi-section-node` 找节点，而这台固件的 CBI 模板渲染的是
   `<div class="cbi-section-node" id="cbi-homeproxy-cfgXXXX">`
   （`/usr/lib/lua/luci/view/cbi/tsection.htm:26`）。选择器一个都匹配不到，
   `decorate()` 空转、`sortNodes()` 在 `list.length < 2` 上提前返回。

第 2 条放开的同时补了状态页两处 `innerHTML` 转义：节点名（订阅可以决定）
和连接表的 host（局域网客户端自己发的 SNI）原本都是原样拼进 HTML 的。

## r26 → r27 修掉的问题：看门狗攥着 procd 的锁不放

**症状**：`/etc/init.d/homeproxy stop`、`reload`、`restart` 和 `opkg install`
全部永久卡死。第一次发现是装 r26 的时候 —— opkg 停在 prerm 的
`/etc/init.d/homeproxy stop` 上四分钟没动，包数据库停在事务中间。

**根因**：`/etc/rc.common` 的 `start()` 一进来就通过 `procd_lock`
（`/lib/functions/procd.sh:55`）拿服务的锁：

    exec 1000>"/tmp/lock/procd_homeproxy.lock"
    flock 1000

它假定拿锁的进程一退出，锁就没了 —— 别的服务都是这样。但 r25 把看门狗从
「跑一会儿就退」改成了常驻，于是 `start-stop-daemon` fork 出来的那个 fd 被
一直继承着，锁在服务活着的整个期间都被一个永远不会退出的进程拿着。

而 `stop()` 和 `reload()` 开头也是 `procd_lock`：先 `flock -n 1000` 试一下，
失败就落到下一行的阻塞版 `flock 1000` 上等 —— 一等就是永远。

**顺带废掉的是看门狗自己的恢复路径**：`try_recover()` 发起的
`/etc/init.d/homeproxy restart` 走的正是这条死锁的路，所以那份「代理死了就
替你拉一把」的保险从来没生效过。

**修法**：`firewall-guard.sh` 在开头 `exec 1000>&-`。fd 1000 是 procd 的，
脚本里没人用它，关掉之后后面 fork 出去的一切（包括恢复用的 helper）都不再
带着它。

**回归测试**：`test/test-firewall-guard.sh` 里新增一项。测试进程先打开
fd 1000 再启动看门狗，假 `firewall.sh` 作为看门狗的子进程报出自己看到的
状态 —— 子进程继承父进程的描述符表，所以那就是看门狗自己的表。删掉
`exec 1000>&-` 再跑，这一项报 `expected [closed], got [open]`。

**注意**：这个 bug 会自己挡住自己的修复 —— 设备上跑着旧版看门狗时，装这个包
的 prerm 一样会卡在 `stop` 上。所以升级前要先手动解锁，否则 `opkg install`
会挂在那里不动。设备上没有 `lsof` 也没有 `fuser`，而且 `/proc/locks` 里**不写文件名**，只写
`主:次:inode`，所以 `grep procd_homeproxy /proc/locks` 是永远匹配不到的。
实际有效的做法：

    # 哪个进程打开了 fd 1000 —— 这就是真凶，直接看这个
    for p in /proc/[0-9]*; do
        [ -e "$p/fd/1000" ] && echo "$(basename $p) $(tr '\0' ' ' < $p/cmdline)"
    done

    # 想确认锁本身（可选）：先拿 inode，再去 /proc/locks 里找
    ls -i /tmp/lock/procd_homeproxy.lock      # 注意 ls -i 前面有空格，别用 cut 切
    cat /proc/locks                            # 形如 2: FLOCK ... <pid> 00:11:<inode>

    # 杀掉持有者和排在它后面的 flock，等待链自然就散了
    kill <fd-1000 的 pid>

**`/proc/locks` 里显示的 pid 不是真凶**：它记的是"创建这把锁的进程"，那个
进程（比如开机时的 `start`）通常早就退出了，显示出来的是个已经不存在的 pid。
真正让锁活着的是继承了那个 fd 的常驻子进程 —— 也就是上面第一个循环找到的
那个。本项目实测：`/proc/locks` 说持有者是 6582（已不存在），实际持有 fd 的
是看门狗 6637。

## r27 → r28：一轮对着设备做的审计，修掉 8 个

这一轮不是猜的，是拿 30 个 agent 把这个包对着跑起来的系统审了一遍，21 条结论
经过对抗性复核活下来，去掉重复的和 r26 已经修过的，落地 8 个。

**1. 看门狗的 acquire 条件是锁存的（`firewall-guard.sh`）。** 原来写的是
`if [ "$ready_port" = "0" ]`，意思是一旦见过端口在监听，后面再也不测了，
安装与否是拿这个记忆判断的。冷启动时 sing-box 几秒内就绑上 :5330，调制解调器
要几分钟 —— 所以端口永远先被看到。如果这中间 sing-box 死了（OOM，或者已经
耗尽 procd 五次重生的崩溃循环），这个陈旧的标志会在 WAN 和 DNS 第一次变绿的
那个 tick 授权安装，把整套捕获装在死端口前面 —— 正是这个脚本存在的意义所要
防的那个状态 —— 而且成功日志还会写"proxy listening on :5330"。现在每个 tick
重新读。回归测试：`test_a_dead_listener_does_not_authorise_the_install`，
把锁存改回去它会失败，日志里那句"proxy listening"照旧打出来。

**2. hotplug 钩子用 `pidof sing-box` 判断存活，而这个判断在整个 stop 窗口里
都是真的。** `stop_service` 先跑 `stop_guard`（删掉 guard.pid），再跑
`firewall.sh down`，而 rc.common 要等 `stop_service` 返回才杀服务 —— 这整段
时间里 sing-box 还在进程表里、规则已经没了。这时任何一个接口事件（这台固件的
`10-eqos` 每个事件都触发）都会让钩子通过全部闸门，把规则装在正在被停掉的代理
前面；如果是单纯的 `stop`，之后再没有任何东西会把它撤掉：会撤规则的看门狗
已经死了，钩子自己后面几轮看到 `check` 通过就退出。现在改成测代理端口在不在
听 —— 和看门狗用的是同一个判断。

**3. `stop_guard` 先收子进程再发信号。** `pgrep -P` 和 `kill` 是两个时刻，
中间看门狗并没有被挡住，而它每个 tick 都 fork（`netstat`、`ip route`、
`nslookup`，重试安装时还有 `firewall.sh`）。这个空档里 fork 出来的子进程逃过
清理，被 init 收养后跑完 —— 一个已经在 `up` 里的 `firewall.sh` 会在
`stop_service` 的 `down` 之后把规则重建起来，而这时候已经没有任何东西能撤掉
它。现在先 `kill -STOP` 再收：停住的进程不可能 fork，窗口是关掉而不是缩小。

**4. 规则集刷新脚本在整体失败时也盖节流戳。** 戳是节流唯一的记忆，无脑
`touch` 让"全失败"和"成功"长得一样：重启时调制解调器还在拨号的 cron、或者没
WAN 时 postinst 的 `--force`，都会写下戳并把下一次尝试推到整整
`rule_set_interval`（默认一周）之后。而对一个**缺失或被截断**的文件来说，这个
节流是唯一的自动修复途径 —— 修不上，confgen 就退回 `type: remote`，正是这套
本地文件要消除的启动期下载。现在只有成功才盖戳，部分失败也算失败。

**5. 下载共用一个固定临时路径且没有锁。** cron（6 小时）和 postinst 的
`--force` 会重叠；两个 curl 用 `-o` 打开同一个路径，各自验证磁盘上的东西，
谁最后 `mv` 谁就可能把一个混合了两个下载的文件装上去 —— 它过得了大小和 magic
检查，然后在 sing-box 启动时炸掉。临时名现在带进程号，脚本整体加锁。

**6. 规则集一变就重启整个服务。** 不需要：在设备上确认了 sing-box 监视规则集
所在目录并在文件被替换时重载。证据是读运行中的进程 —— `ls -l /proc/$(pgrep -f
'sing-box run')/fd` 有三个 `anon_inode:inotify`，每个的 `fdinfo` 都指向同一个
被监视 inode 89，也就是 `/etc/homeproxy/rule_set`，mask `fc6` 包含
`IN_MOVED_TO` 和 `IN_CREATE` —— 正是脚本那句 `mv -f tmp dst` 产生的事件。
重启的代价不只是抖一下：stop 会撤掉防火墙规则，start 重新进看门狗的 acquire
闸门，要端口、WAN、DNS 三样都绿规则才回来。WAN 恰好不在时，局域网就停在直连
上等闸门打开 —— 在这台设备的调制解调器上那是几分钟 —— 只为了加载一个
sing-box 早就重载过的文件。

**7. 生成器自己的保留 tag 没被去重覆盖（`confgen.lua`）。** 去重循环的理由写
得很清楚（"sing-box rejects duplicate tags"），但它只查其他**节点**，
`direct` / `block` / `proxy` 三个固定 outbound 是循环之后追加的，从来不查。
所以一个显示名叫 `direct` 的节点会产生两个同名 outbound，sing-box 在构造期就
拒绝注册并退出，procd 把它变成崩溃循环 —— 表现就是"启动了但没反应"，LuCI 上
没有任​​何解释。不需要两个节点，一个叫 `direct` 的就够。

**8. 订阅更新的两个按钮把整个抓取同步跑在 LuCI 请求里。** `luci.sys.call`
会一直等到脚本结束，而 subscribe.lua 是串行抓的，每个 `--connect-timeout 15
--max-time 120` 且没有总预算 —— 一个黑洞 URL 15 秒，一个连上但不说话的 URL
两分钟，乘以订阅数（过期的机场就是全部）。uhttpd 的 `script_timeout` 默认
60 秒，超时就 SIGKILL 请求进程，所以用户看到的是 60 秒后一个 502；而
subscribe.lua 是**孙进程**（`luci.sys.call` 走 `sh`），那个 SIGKILL 到不了
它，抓取继续跑完只写进日志，再点一次就叠第二个。现在像状态页的 TCP 全量测速
一样后台起，页面本来就有的日志面板负责汇报进度。

顺带两处小修：subscribe.lua 加锁（本来没有任何串行化，两次重叠的运行会丢掉
其中一次刚导入的节点，而且**每订阅的 `last_update` 戳是另一次 uci 调用、它会
留下来**，于是下一次自动重试被压制整个间隔 —— 比普通丢更新更糟，因为完全
静默）；手工添加的 hysteria2 节点，Obfs Password 会被保存然后丢掉，因为生成
器要求 `obfs_type == "salamander"` 而这个字段只有链接解析器会写。

### 还没动的（需要先做决定，不适合顺手改）

审计还活了 4 条，都指向**同一个根因：节点的身份是什么**，改动面比上面这些大，
留着单独处理：

- `default_node` 存的是 UCI section 名，而 outbound tag 是显示名，显示名不
  唯一、重名后缀每次生成都重算且从不写回；匿名 section 的名字是库按内容派生
  的，删掉一个节点之后默认节点指向谁需要单独确认。
- 订阅归属是按订阅 section 的**自动生成名**匹配的，那个 section 一移动，
  "Update" 就会静默匹配不上。
- 粘贴同一个链接两次永远产生两个完全一样的节点，没有任何去重（这次手工删的
  那个重复节点就是这条）。

## r28 → r29：页面上出现两条菜单

**症状**：每个 homeproxy 页面上都有两条标签栏，上面五条（运行状态 / 节点设置 /
订阅 / 添加节点 / 日志），下面四条（没有「添加节点」）。

**根因**：这个包自己画了一条，主题又画了一条。

`view/homeproxy/nav.htm` 存在的原因是**厂商主题不画**子页面标签栏 —— 它的
header 把 NRadio 自己的导航写死了，只拿 `disp.node_childs` 当判断条件。这句话
对着厂商原主题是对的，但这个设备跑的是 **argon**，而 argon 画：它的 header 里有
一个空的 `<div id="tabmenu">`，由 `/luci-static/resources/menu-argon.js` 的
`renderTabMenu()` 在运行时按菜单树填进去 —— 填的就是全部五个子页面，包括
`import` 这个 `call()` 入口，那条恰恰是 nav.htm 的列表里从来没有的。

所以两条都在，一条五个、一条四个，叠在一起。

**修法**：`nav.htm` 先问主题画不画，画就整个不输出。

判据是**主题自己的 header**，因为两种机制都锚在那里：服务端渲染的主题在 header
里遍历 `disp.node_childs`，客户端渲染的主题在 header 里放那个容器等自己的 JS 去
填。两个都查。主题识别不出来时**照旧渲染** —— 少一条标签栏会让五个页面只能靠
敲 URL 走，多一条只是难看，要错就往这个方向错。

**验证**（在设备上抓真实页面，四个页面各一次）：

    status        http=200  our strip=0  argon strip=1
    node          http=200  our strip=0  argon strip=1
    subscription  http=200  our strip=0  argon strip=1
    log           http=200  our strip=0  argon strip=1

模板语法用 LuCI 自己的解析器预先编译过（`luci.template.parser` 是个 C 模块，
`parse_string()` 直接返回编译好的函数），并且用一个故意写坏的模板作为反向对照
确认这个检查会失败 —— 否则「编译通过」可能只是因为检查根本没在检查。

## r29 → r30：折叠条上终于有节点信息了

**症状**：节点页每个节点确实被折成了一行，但那一行永远是 `(unnamed)`，后面
跟着一个空地址 —— 等于什么都没显示。

**根因**：CBI **不把值放在它给了 id 的那个元素上**。

抓下来的真实页面长这样：

    <div id="cbid.homeproxy.cfg0546ab.name" data-idref="15bcc5b1">
      <input id="widget.cbid.homeproxy.cfg0546ab.name" value="node-example">
    </div>

`#cbid...` 是个**包裹用的 div**，真正的控件是 `/luci-static/resources/cbi.js`
在运行时建好塞进去的。div 没有 `.value`，所以 `field()` 每次都拿到
`undefined` → 空字符串 → 折叠条显示 `(unnamed)`。`server`、`port` 同理。

**第二个根因（时间差）**：即使读对了元素，**创建折叠条的那一刻页面上还没有
这些控件**。cbi.js 建控件不是在 `DOMContentLoaded`：luci.js 先等
`DOMContentLoaded`，再等四个 promise 链上的依赖，其中
`probeRPCBaseURL()` 是一次**网络往返**，然后才调 `cbi_init()`。所以折叠条是
在控件存在之前建好的。

**修法**：

- `field()` 降一层找真正的控件（`select` / 非 hidden 的 `input` / `textarea`）。
- `refreshSummaries()` 在建完之后**重写**摘要，由三个时机驱动：luci.js 建完
  时发的 `luci-loaded` 事件、一个有上限的 250ms 重试（40 次，字段答上来就
  停；`luci-loaded` 只在探测成功时才发，所以不能只靠它）、以及 document 上
  委派的 `change` / `widget-change` —— 改名字时折叠条跟着变，而不是留着旧名字。
- 折叠条上顺便显示节点类型。

**顺带修掉的两个**：

- **排序会把「删除」按钮留在原地**。`tsection.htm` 把一节的删除按钮放在
  **它自己前面**的兄弟 div 里，只有 body 带可识别的 id。原来只搬 body，于是
  TCP 扫一遍重排之后，每个删除按钮都挨着**别的**节点 —— 按下去删的是另一台
  服务器。现在按钮和 body 作为一对一起搬，而且插在 Add 按钮**之前**（原来是
  `appendChild`，会跑到 Add 后面去）。
- 加了一个「Expand all / Collapse all」按钮，标签永远显示**点下去会发生什么**
  （手点开单个节点之后它会跟着变）。

**验证**（不是读代码，是真的在浏览器里跑）：

把设备上的静态资源整棵（5.7 MB）拉到本地起一个镜像站，再给 `/ubus` 和 action
接口套一个桩，然后用 headless Chrome 真正渲染这个页面、真正点按钮。桩代码在
`test/browser/`（见下）。结果：

    控件建好后再读         name="我的节点" type="vless" addr="node.example.com:8443"
    初始状态               open=false 展开数=0  「Expand all」
    点 Expand all          open=true  按钮变「Collapse all」
    再点一次               open=false 按钮变回「Expand all」
    点单个节点的表头       只有它展开，按钮跟着变「Collapse all」
    改名字（真的往 <input> 里写值再派发 change）  折叠条立刻变成新名字
    两个节点 + 两节各一个删除按钮 → 排序后逐对检查
                          OK 每个删除按钮仍跟着自己的节点
                          OK 最快的节点排到了最上面

## 改配置后自测（在设备上跑，不动真实流量）

    scp gen.lua root@192.168.66.1:/tmp/
    ssh root@192.168.66.1 'lua /tmp/gen.lua empty'   # 空配置
    ssh root@192.168.66.1 'lua /tmp/gen.lua noded'   # 带两个假节点

输出会写到一个临时文件，再拿 `sing-box check -c <文件>` 验证。这样改完配置
生成器不用装包就能知道生成的 JSON 还能不能过 sing-box。

## 针对这台设备固件的三处适配（换设备要重新看）

1. `/etc/init.d/eqos` 会 `iptables -t mangle -F PREROUTING`，而
   `/etc/hotplug.d/iface/10-eqos` 每个接口事件都调它 —— 规则会被静默清掉。
   对应 `data/etc/hotplug.d/iface/99-homeproxy` 负责重装。
2. `dhcp.@dnsmasq[0].dns_redirect=1` 在 nat 层 -95 抢 UDP 53，和 TPROXY 冲突。
   对应 `data/usr/share/homeproxy/firewall.sh` 里的 `SKIP_DNS_UDP`。
3. 和 PassWall 撞车：fwmark 用 480、路由表用 120（PassWall 占着 1 和 100）。
