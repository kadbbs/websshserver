# 配置与部署

[← 返回 README](../README.md)

## 默认端口与监听地址

```bash
sudo ./bin/sshserver
```

| 入口 | 默认监听地址 | 行为 |
| --- | --- | --- |
| TCP SSH | `127.0.0.1:22` | 未传入 `-tcp` 时，端口占用后尝试 `127.0.0.1:22223` |
| WebSocket | `127.0.0.1:22222` | 网页客户端也默认填写 `22222` |

备用端口同样被占用时启动失败；权限不足等其他错误会直接报出。实际监听地址以启动日志为准。

显式设置 `-tcp` 会关闭自动切换，即使指定的是 `22`。空字符串可以关闭相应入口：

```bash
# 自定义对外监听地址。
sudo ./bin/sshserver -tcp :22223 -http :22222 -origin null

# 仅开启 TCP。
sudo ./bin/sshserver -http ''

# 仅开启网页连接。
sudo ./bin/sshserver -tcp '' -http :22222 -origin null
```

## 参数

| 参数 | 默认值 | 用途 |
| --- | --- | --- |
| `-tcp` | `127.0.0.1:22` | TCP SSH 地址；未指定时启用 `22 → 22223` 端口回退 |
| `-http` | `127.0.0.1:22222` | WebSocket HTTP 地址 |
| `-host-key` | `data/ssh_host_ecdsa_key` | 持久化主机私钥；首次自动生成 P-256 ECDSA 密钥，权限 `0600` |
| `-pam-service` | `sshd` | `/etc/pam.d/` 下的 PAM 策略名 |
| `-origin` | `$SSH_WS_ORIGINS` | 浏览器来源白名单，逗号分隔；本地文件用 `null` |
| `-tls-cert` / `-tls-key` | 空 | HTTPS / WSS 证书和私钥 |
| `-max-connections` | `64` | 两种入口合计最大连接数 |
| `-rekey-bytes` | `67108864` | 每方向 SSH 密钥更新阈值，最小 `256` 字节 |

服务端仅提供 `/ssh` 和 `/healthz`，网页文件独立部署。

## PAM 与系统账户

服务端针对 Linux + PAM，启动需要 root。系统账户由 NSS 查询，密码经 PAM 校验。登录后使用该用户的 UID、GID、补充组、HOME、工作目录和登录 Shell。

默认使用 `/etc/pam.d/sshd`，策略文件需要存在。Debian / Ubuntu 缺少该策略时，可以安装项目附带的示例：

```bash
sudo apt-get install libpam0g libpam-modules
sudo install -m 0644 config/pam.d/webssh /etc/pam.d/webssh
sudo ./bin/sshserver -pam-service webssh -origin null
```

此示例依赖 Debian / Ubuntu 的 `common-auth`、`common-account`、`common-session`。其他发行版应使用对应的系统 PAM 策略。

每条 SSH 连接使用独立的 Go 工作进程，PAM 调用和 Shell 启动固定在进程主线程。认证后建立 PAM 凭据和会话，连接结束时关闭会话、清理凭据；PTY 所有者也会设置为登录用户。

账户有效性、root 登录限制等由本服务采用的 PAM 策略控制。服务端自身实现 SSH，不读取 OpenSSH 的 `sshd_config`。当前支持密码和普通公钥认证；额外交互提示、密码变更及键盘交互认证尚未实现。Go 工作进程包含运行时线程，不支持要求整个进程完全单线程的 PAM 模块，例如 `pam_namespace`。

## 系统用户公钥

原生客户端可使用登录用户的 `~/.ssh/authorized_keys`，认证后仍需通过 PAM 账户检查和会话初始化：

```bash
ssh -i ~/.ssh/id_ed25519 -p 22223 系统用户名@服务器IP
```

HOME、`.ssh` 和公钥文件需要由该用户或 root 所有，且不能被组或其他用户写入。支持普通公钥和注释；带 `command=`、`from=` 等限制选项的条目及证书会被拒绝。网页目前使用密码登录。

## 独立网页与来源设置

直接打开 `client/ssh-client.html` 时，服务端允许本地文件来源：

```bash
sudo ./bin/sshserver -origin null
```

网页只需填写服务器地址、端口、系统用户名和密码。地址支持 IP、IPv6 和主机名。已有保存的连接使用原设置的端口；密码不写入本地存储。

开发时也可以单独托管分文件版本：

```bash
python3 -m http.server 9000 --bind 127.0.0.1 --directory client
sudo ./bin/sshserver -origin http://127.0.0.1:9000
```

打开 `http://127.0.0.1:9000`。Origin 使用精确匹配；多个来源以逗号分隔，例如 `-origin 'http://127.0.0.1:9000,null'`。同源浏览器请求可以连接；不带 Origin 的原生 WebSocket 客户端仍需通过 SSH 认证。

## HTTPS / WSS

浏览器加密能力需要安全上下文：本地文件、localhost、127.0.0.1 或 HTTPS。通过远程网站托管网页时使用 HTTPS，并为 SSH 服务端配置 TLS：

```bash
sudo ./bin/sshserver -http :8443 \
  -origin https://terminal.example.com \
  -tls-cert /path/to/fullchain.pem \
  -tls-key /path/to/privkey.pem
```

网页填写 `server.example.com` 和端口 `8443`，证书需要被浏览器信任。也可由反向代理终止 TLS，转发 `/ssh` 的 WebSocket Upgrade。

网页会根据 HTTPS 环境、常见 TLS 端口和之前成功的连接选择传输方式。使用本地文件或 HTTP 页面时，只在传输尚未建立的情况下尝试另一种方式；HTTPS 页面始终使用 WSS。认证失败、拒绝指纹或 SSH 校验失败时不会自动重试。

主机指纹绑定到服务器地址和端口，并兼容旧版按 URL 保存的指纹。首次连接和指纹变化时需要用户确认。
