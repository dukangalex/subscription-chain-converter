# 一键部署 · One-Click Deploy

把自托管订阅转换后端（页面服务 + 链式构建器 + subconverter + 官方规则
镜像）装到一台新服务器上，只需要一条命令。设计规格见仓库根目录的
README.md。

## 前提

- 一台 Linux 服务器（x86_64 或 arm64），有公网出口
- root 权限
- 一个你自己的域名（之后用隧道或反向代理把流量指进来）
- python3、curl、tar（脚本会检查；PyYAML 缺失时自动安装）

## 部署

```bash
cp config.env.example config.env
# 编辑 config.env，至少改 DOMAIN 为你的域名
sudo bash install.sh
```

脚本依次完成：落文件到 `INSTALL_DIR`（默认 `/opt/subconv`）→ 把骨架
里的规则地址替换成你的域名 → 下载 subconverter（官方发布，固定版本，
只监听回环）→ 按需下载 Node.js（仅回退路径需要）→ 注册并启动 systemd
服务（subconverter、subpage、rules-refresh.timer）→ 首次灌满规则
镜像 → 自检（版本探活、首页、规则下发、用虚拟节点走一遍短链生成
链式配置并验证 detour 串联）。

任何一步失败脚本会停下并说明原因，不会留下半成品状态对外服务。

## 部署后：接入公网

脚本不会碰你的域名解析和隧道配置。安装结束时会打印一段 ingress
分流片段（Cloudflare Tunnel 版），把你域名的 `/`、`/chain`、`/conv`、
`/sub`、`/version`、`/shorten`、`/(c|m|s)/`、`/rules/` 指向
`127.0.0.1:<PAGE_PORT>` 即可。用 nginx/Caddy 等反代时按同样路径改写。

完成后打开 `https://<你的域名>/` 即可生成短链订阅。

## 重跑与卸载

- 重跑 `install.sh` 是安全的：旧安装整体备份为
  `<INSTALL_DIR>.bak-<时间戳>`，短链映射 `links.json` 与规则镜像
  `rules_files/` 自动带到新安装里，不丢数据。
- 改域名：改 `config.env` 的 DOMAIN 后重跑即可（骨架里的规则地址会
  重新替换；已生成的客户端配置需要重新拉取一次订阅）。
- 卸载：`systemctl disable --now subpage subconverter rules-refresh.timer`
  并删除 `/etc/systemd/system/` 下的四个单元文件与安装目录。

## 无 systemd 环境试跑

容器或 CI 里验证部署包本身：`NO_SYSTEMD=1 INSTALL_DIR=/tmp/subconv bash install.sh`
——文件照常落盘、规则照常灌满，并会临时拉起服务跑完同一套自检再退出。
