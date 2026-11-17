# 协议与兼容性

[← 返回 README](../README.md)

## 连接结构

TCP 与 WebSocket 入口接受相同的 SSH 2.0 字节流，WebSocket 使用二进制帧。Go 服务端自身实现 SSH 协议，认证通过 PAM 对接系统账户。

网页在浏览器内执行 SSH 握手、主机签名校验、加解密、密码认证和终端交互。单文件版本内嵌全部 CSS、JS 和图标，可以独立复制和托管。

## 网页客户端算法

| 项目 | 当前支持 |
| --- | --- |
| SSH 版本 | SSH 2.0 |
| 密钥交换 | `ecdh-sha2-nistp256` |
| 主机密钥与签名 | `ecdsa-sha2-nistp256` |
| 加密 | `aes128-ctr` |
| 消息完整性 | `hmac-sha2-256`，验证序号与 MAC |
| 压缩 | `none` |
| 用户认证 | `password` |
| 会话 | PTY Shell、窗口调整、退出状态 |
| 密钥更新 | 支持双方发起；网页每 30 分钟或约 64 MiB 数据后发起 |

默认生成的 ECDSA P-256 主机密钥与网页兼容。替换为仅 RSA / Ed25519 主机密钥后，普通 SSH 客户端仍可使用，但当前网页无法协商。

Go 服务端使用 `golang.org/x/crypto/ssh` 的默认算法集合，原生客户端还可使用普通公钥进行认证。

## 终端能力

支持 ANSI、256 色、真彩色、光标与擦除、滚动区域、备用屏幕、常见功能键、Ctrl 组合键、中文输入、粘贴和 2000 行回滚。界面提供字号调节、收起连接栏、复制、清屏、全屏、会话计时和手机快捷键。

未实现全部 xterm 扩展、鼠标上报及复杂 emoji 排版。

## SSH 功能范围

| 功能 | 状态 |
| --- | --- |
| 交互式 Shell / PTY | 支持 |
| 远程命令、标准输入输出、退出状态 | 支持 |
| 多个 session、窗口调整、常见信号 | 支持 |
| 密码 / 系统用户普通公钥认证 | 支持 |
| SFTP、端口转发、agent 转发、X11 转发 | 尚未实现 |
| PAM 改密、键盘交互、多轮交互提示 | 尚未实现 |

## 参考

- [SSH Transport · RFC 4253](https://www.rfc-editor.org/rfc/rfc4253)
- [SSH Authentication · RFC 4252](https://www.rfc-editor.org/rfc/rfc4252)
- [SSH Connection · RFC 4254](https://www.rfc-editor.org/rfc/rfc4254)
- [AES-CTR · RFC 4344](https://www.rfc-editor.org/rfc/rfc4344)
- [ECDH / ECDSA · RFC 5656](https://www.rfc-editor.org/rfc/rfc5656)
- [Go PAM binding](https://github.com/msteinert/pam)
