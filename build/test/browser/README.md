# 节点页的浏览器测试

这三个文件不测 Lua、也不测生成的配置，测的是**页面上的 JavaScript 真的做了什么**。
读代码读不出这一点：`node.js` 依赖 LuCI 在运行时才建出来的控件，而控件什么时候
出现、值放在哪个元素上，只有真渲染一遍才知道。

## 为什么要起镜像站

页面要跑起来得连 `/luci-static/` 下的东西，还得有一个能应答的 RPC 后端 ——
luci.js 是先探测 RPC 端点、探测成功才开始建控件的。所以：

1. 把设备上整棵静态资源拉下来（约 5.7 MB）：

       ssh root@192.168.66.1 'cd /www && tar cf - luci-static | gzip -9 | base64' > assets.b64

2. 抓一份真实页面存成 `page.html`（要先登录拿 cookie）：

       curl -c cj --data-urlencode luci_username=root --data-urlencode luci_password=... \
            http://192.168.66.1/cgi-bin/luci/
       curl -b cj -o page.html http://192.168.66.1/cgi-bin/luci/admin/services/homeproxy/node

3. 把文件摆成这样（`page.html` 和 `luci-static/` 平级），起桩服务：

       python3 -I serve.py <镜像目录> 18090

## 跑

交互测试（折叠、展开全部、点表头、改名字）：

    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless \
      --disable-gpu --user-data-dir=/tmp/cp1 --virtual-time-budget=20000 \
      --dump-dom "http://127.0.0.1:18090/test-interactions.html"

排序测试（需要两个节点：脚本会克隆一节，然后重新注入 node.js，并用
`sorting-action.json` 假装刚扫完一遍 —— 一个失败、一个 50ms）：

    python3 -I serve.py <镜像目录> 18091 sorting-action.json
    ... --virtual-time-budget=30000 --dump-dom ".../test-sorting.html"

结果直接印在页面上的 `<pre id=out>` 里，`--dump-dom` 会把它一起吐出来。

## 这两个脚本为什么值得留着

`test-sorting.html` 里那一段「逐对检查删除按钮有没有跟着自己的节点」，是照着
一个真的修掉的 bug 写的：排序原来只搬节点 body，而 `tsection.htm` 把删除按钮
放在 body **前面**的兄弟 div 里 —— 重排之后每个删除按钮都挨着别的节点。
