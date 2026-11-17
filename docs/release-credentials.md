# 自动发版凭证指南

本文说明如何为本仓库（`nekohashizuku2333333333/mio-rs`）创建自动发版所需的凭证。
结论先行：**GitHub Release 不需要手工创建 Token；crates.io 首次发布必须手工创建一次
API Token，之后可以切换到 OIDC 可信发布，做到不再保存长期密钥。**

## 1. 凭证总览

| 发版目标 | 需要的凭证 | 创建位置 | 生命周期 | 最小权限 |
| --- | --- | --- | --- | --- |
| GitHub Release / 附件 | `GITHUB_TOKEN` | Actions 自动注入，无需创建 | 单次 Job，最长 6 小时 | `contents: write` |
| 从本机/外部定时任务 push tag | SSH Deploy Key 或 Fine-grained PAT | 仓库 Settings → Deploy keys / 个人 Settings → Developer settings | 长期（可随时撤销） | 仅该仓库 `Contents: Read and write` |
| crates.io 首次发布 | crates.io API Token | <https://crates.io/settings/tokens> | 建议 30–90 天 | `publish-new` + `publish-update`，crate scope `mio-rs` |
| crates.io 后续发布 | OIDC 临时 Token | 工作流中由 `rust-lang/crates-io-auth-action` 交换 | 30 分钟 | `id-token: write` |

## 2. GitHub Release：使用自动 `GITHUB_TOKEN`

GitHub Actions 在每个 Job 开始时自动创建 `GITHUB_TOKEN`，它只对当前仓库有效，Job
结束即失效。**不要在仓库 Secrets 里再手工建一个同名 Token。**

在 release workflow 中显式声明权限：

```yaml
permissions:
  contents: write
```

然后创建 Release 或上传附件时使用 `${{ secrets.GITHUB_TOKEN }}`（也可用
`${{ github.token }}`）。这是创建 Release 所需的最小权限；`contents: read` 不够。

如果仓库设置把默认 Token 权限设为只读，工作流里的 `permissions:` 仍然可以把它提升到
`contents: write`。若组织策略禁止提升，需要管理员在组织/仓库 Actions 设置中允许。

## 3. crates.io 首次发布：手工创建 API Token

crates.io 的 OIDC 可信发布有一个硬性前提：**crate 必须已经存在于 crates.io**。
因此第一次发布必须使用 API Token。

### 3.1 创建 Token

1. 登录 <https://crates.io>。
2. 打开 <https://crates.io/settings/tokens>，点击 **New Token**。
3. 名称填 `mio-rs-release`。
4. 过期时间建议 30–90 天；发版完成后可撤销。
5. 权限只勾选：
   - `publish-new`（首次创建 crate 必需）
   - `publish-update`（后续版本必需）
6. crate scopes 填 `mio-rs`（不要用 `*`）。
7. 创建后**只显示一次**，立即复制保存到密码管理器。

### 3.2 在本地首次发布

```bash
cargo login
# 粘贴 Token；默认写入 ~/.cargo/credentials.toml
cargo publish --dry-run
cargo publish
```

`cargo login` 默认把 Token 明文写入 `~/.cargo/credentials.toml`。更安全的做法是配置
系统钥匙串 credential provider：

```toml
# ~/.cargo/config.toml
[registry]
global-credential-providers = ["cargo:token", "cargo:libsecret", "cargo:macos-keychain", "cargo:wincred"]
```

### 3.3 在 GitHub Actions 中首次发布

把 Token 保存为仓库 Secret（Settings → Secrets and variables → Actions → New repository
secret），名称 `CARGO_REGISTRY_TOKEN`，然后在发布步骤注入：

```yaml
- run: cargo publish --locked
  env:
    CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
```

首次发布成功后，建议删除该 Secret，切换到下一节的 OIDC。

## 4. crates.io 后续发布：OIDC 可信发布

### 4.1 在 crates.io 配置

1. 打开 crate 页面 → **Settings** → **Trusted Publishing** → **Add**。
2. 选择 GitHub，填写：
   - Repository owner：`nekohashizuku2333333333`
   - Repository name：`mio-rs`
   - Workflow filename：`publish-crates.yml`
   - Environment：`release`（可选，但推荐）
3. 保存。

这三个字段必须与工作流完全一致；`workflow filename` 只写文件名，不写路径。

### 4.2 工作流配置

仓库已经提供 `.github/workflows/publish-crates.yml`，核心配置为：

```yaml
on:
  push:
    tags: ["v*"]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  publish:
    if: github.event_name == 'workflow_dispatch' || vars.CRATES_IO_TRUSTED_PUBLISHING == 'true'
    runs-on: ubuntu-24.04
    environment: release
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@stable
      - uses: rust-lang/crates-io-auth-action@v1
        id: auth
      - run: cargo publish --locked
        env:
          CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}
```

`crates-io-auth-action` 会用 GitHub OIDC 身份向 crates.io 换取 30 分钟有效的临时
Token，并在 Job 结束时自动撤销。仓库中不需要保存任何 crates.io 长期密钥。

首次手工发布并配置好可信发布后，在仓库 Settings → Secrets and variables → Actions →
Variables 中新建变量 `CRATES_IO_TRUSTED_PUBLISHING=true`，此后推送 `v*` tag 才会自动
发布到 crates.io。这样在 crate 尚不存在时，tag 不会因 OIDC 发布失败而整体报红。


### 4.3 限制条件

- 触发事件不能是 `pull_request_target` 或 `workflow_run`；使用 `push` tag 或
  `workflow_dispatch`。
- workflow 文件名、仓库 owner/name、environment 必须与 crates.io 配置逐字匹配。
- crate 必须已存在且当前账号是 owner。
- Token 只对配置中列出的 crate 有效。

## 5. 自动打标签：Deploy Key 或 Fine-grained PAT

如果每日同步任务需要自己 push 版本 tag，GitHub Actions 的 `GITHUB_TOKEN` 不能直接被
本机进程使用。两种选择：

### 方案 A：SSH Deploy Key（推荐）

1. 本机生成专用密钥：
   ```bash
   ssh-keygen -t ed25519 -C "mio-rs-release" -f ~/.ssh/mio_rs_deploy -N ""
   ```
2. 仓库 Settings → Deploy keys → Add deploy key，粘贴
   `~/.ssh/mio_rs_deploy.pub`，勾选 **Allow write access**。
3. 本机 `~/.ssh/config` 指定该仓库使用此密钥。
4. 只能 push 代码/tag，不能调用 GitHub Release API；Release 由 tag 触发的 Actions 完成。

Deploy Key 只作用于这一个仓库，比账号级 PAT 更适合自动化。

### 方案 B：Fine-grained PAT

1. 打开 <https://github.com/settings/personal-access-tokens/new>。
2. Repository access 只选 `mio-rs`。
3. Permissions：
   - `Contents: Read and write`（push 代码和 tag）
   - 只有在自动化需要修改 `.github/workflows/` 时才加 `Workflows: Read and write`
4. 设置较短过期时间，保存到本机密码管理器或 CI Secret。
5. 不要使用 classic PAT 的 `repo` 全仓库权限。

## 6. 推荐的整体架构

```text
每日同步任务（本机）
  └─ 检测上游变化 → 移植 → 验证
       ├─ git push（Deploy Key，仅代码/tag）
       └─ git push tag v0.5.6
              └─ GitHub Actions: release.yml
                   ├─ 构建多平台二进制
                   ├─ GITHUB_TOKEN 创建 GitHub Release + 上传附件
                   └─ OIDC 换取 crates.io 30 分钟 Token → cargo publish
```

这样长期凭证只剩一个仓库级 Deploy Key；GitHub Release 与 crates.io 都使用短生命周期
凭证。

## 7. 本仓库现状与前置检查

已核实（2026-11-17）：

- 仓库当前没有 tag、Release 或 Actions 运行记录。
- 已加入两个工作流：
  - `.github/workflows/release.yml`：tag 触发时验证源码、构建 glibc 二进制并用
    `GITHUB_TOKEN` 创建 GitHub Release。
  - `.github/workflows/publish-crates.yml`：在配置可信发布并设置仓库变量
    `CRATES_IO_TRUSTED_PUBLISHING=true` 后，通过 OIDC 发布到 crates.io。
- crates.io 上 `mio-rs` 尚不存在（API 返回 `crate mio-rs does not exist`），首次发布
  会占用该名称。**因此第一次发布不能用 OIDC**，必须临时使用 API Token；发布成功后
  再按第 4 节配置 Trusted Publishing。
- `cargo package` 产物约 5.6 MiB，低于 crates.io 10 MiB 上传上限。
- `cargo publish --dry-run --locked` 已通过。
- `Cargo.toml` 已补充 `repository` 元数据。
- 当前没有任何 Actions Secret；仓库公开，Secrets 名称只有管理员可见。
- glibc release 构建已验证通过。musl 静态构建在本机因缺少
  `x86_64-linux-musl-g++` 失败，故工作流暂不发布 musl 产物。

### 首次发布的操作顺序

1. 在 crates.io 创建 `mio-rs` API Token（`publish-new` + `publish-update`，scope
   `mio-rs`）。
2. 用该 Token 在本地或一次性工作流中执行 `cargo publish --locked`，让 crate 先存在。
3. 在 crate Settings → Trusted Publishing 添加仓库 `nekohashizuku2333333333/mio-rs`、
   workflow `publish-crates.yml`、environment `release`。
4. 删除长期 `CARGO_REGISTRY_TOKEN`，并在仓库 Actions Variables 中设置
   `CRATES_IO_TRUSTED_PUBLISHING=true`，之后只靠 OIDC 发布新版本。



## 8. 安全检查清单

- [ ] 不把任何 Token 写进仓库、日志或命令历史。
- [ ] crates.io Token 限定 crate scope 与 `publish-*` 端点，设置过期时间。
- [ ] GitHub Release 只用 `GITHUB_TOKEN`，权限限定 `contents: write`。
- [ ] OIDC 工作流绑定 `environment: release`，并配置 required reviewers。
- [ ] 发布 job 只在 `v*` tag 上运行，不在 PR 上运行。
- [ ] 首次发布后删除 `CARGO_REGISTRY_TOKEN` Secret。
- [ ] 定期在 crates.io 与 GitHub 检查并撤销不再使用的 Token/Deploy Key。
- [ ] 开启 crates.io 发布邮件通知，发现异常立即 yank 并撤销凭证。
