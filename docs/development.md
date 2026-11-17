# 开发与发布

[← 返回 README](../README.md)

## 本地开发

需要 Linux、Go 1.26+、C 编译器、Make、Python 3.10+、Node.js 和 PAM 开发包。网页运行时无需这些构建与测试工具。

```bash
sudo apt-get install build-essential libpam0g-dev
make build
make test check
```

Makefile 启用 CGO，并设置 PAM 绑定需要的编译选项。Go 测试和静态检查扫描 `server/`、`internal/`，避免受运行时生成的私有 `data/` 目录影响。

## 项目结构

```text
server/                      服务端入口与参数解析
internal/sshd/               SSH、PAM、用户权限、PTY 与连接进程
client/                     独立网页与浏览器 SSH 客户端
scripts/bundle_client.py    生成单文件 HTML
scripts/package_release.py  打包当前架构服务端与许可证
tests/browser_smoke.py      OpenSSH 与浏览器互通测试
config/pam.d/webssh         Debian / Ubuntu PAM 策略示例
.github/workflows/          tag 构建与发布
```

## 网页维护

修改 `client/index.html`、`style.css`、`ssh.js`、`terminal.js` 或 `app.js` 后更新单文件版本：

```bash
make bundle-client
```

`client/ssh-client.html` 是生成文件，内嵌 MIT 许可证。请将源码和重新生成的文件一起提交，发布工作流会检查它们是否一致。

## 互通测试

```bash
make browser-test-build
python3 -m venv .venv
.venv/bin/pip install -r tests/requirements.txt
.venv/bin/playwright install chromium
.venv/bin/python tests/browser_smoke.py
```

常规测试使用真实 libpam 和临时 PAM 策略，对当前系统用户验证认证、账户拒绝、会话生命周期、Shell 身份、SSH 传输、默认端口回退及自定义参数，不修改宿主账户、密码、公钥或 `/etc/pam.d`。

浏览器测试还覆盖原生 OpenSSH、主机指纹迁移、错误密码、MAC 与签名篡改拒绝、双方 rekey、通道流量控制、TLS 自动选择、单文件页面和手机布局。已有 Chromium 可用 `CHROMIUM_PATH` 指定。

root 切换到另一用户的 UID / GID / 补充组测试，需要具备 UID `1000` 账户的 root 测试环境；普通用户会显示 SKIP：

```bash
sudo ./bin/sshd.test -test.run TestPrivilegedUIDGIDAndSupplementaryGroups -test.v
```

## 本地发布包

```bash
make release
```

在当前 Linux 架构生成 `dist/websshserver_linux_<arch>.tar.gz`、`dist/ssh-client.html` 和 `dist/SHA256SUMS.txt`。压缩包保持项目目录布局，包含：

```text
bin/sshserver
client/ssh-client.html
README.md
LICENSE
config/pam.d/webssh
docs/
THIRD_PARTY_LICENSES/
```

仅收录明确列出的发布文件。Go 运行时和已编入服务端的依赖许可证从实际构建信息、当前工具链和模块缓存收集。

## GitHub Actions

工作流：[`.github/workflows/release.yml`](../.github/workflows/release.yml)。

推送任意 tag 时触发，分为三个阶段：

1. **Verify**：Go 竞态测试、静态检查、网页语法与生成文件一致性检查、OpenSSH 与浏览器互通测试。
2. **Build**：在 Ubuntu 22.04 的 `amd64` / `arm64` 原生 runner 上编译和打包，保留 CGO / PAM 支持。
3. **Release**：汇总产物，生成 SHA-256 校验文件，创建 GitHub Release。重复运行时更新同一 Release 的附件。

使用 GitHub 提供的 `GITHUB_TOKEN`，只有 Release 阶段申请 `contents: write`。Actions 依赖固定到提交 SHA。

先提交并推送代码，再推送版本 tag：

```bash
git push -u origin main
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

如需校验下载文件，将压缩包、独立网页和校验文件放在同一目录运行：

```bash
sha256sum --check SHA256SUMS.txt
```

参考：[GitHub runner](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job)、[GitHub Release CLI](https://cli.github.com/manual/gh_release_create)。
