# 上游同步流程

本仓库跟踪 [orgmio/mio](https://github.com/orgmio/mio)。每日检查以
[`upstream.lock.toml`](../upstream.lock.toml) 中最后一次“已移植且已核验”的提交为基线。

## 自动任务

每日 08:00（Asia/Taipei）执行以下流程：

1. 运行 `./scripts/check_upstream.sh` 获取上游 `main`、标签和版本常量。
2. 若退出码为 `0`，记录“无变化”，不改动工作区。
3. 若退出码为 `10`，逐项检查 `locked_commit..origin/main` 的提交和补丁，将其中的
   配置、协议、传输、CLI 行为移植到 Rust 实现；协议未变时不要把二进制版本误当作
   协议版本。
4. 更新受影响的文档和针对性测试，再运行 `./scripts/verify_all.sh`。该脚本固定使用
   仓库内 `target/`，并以 Cargo `--locked` 模式运行，避免依赖或锁文件漂移。
5. 只有全部检查通过后，才更新 `upstream.lock.toml` 的提交、标签和版本。
6. 核验失败时保留工作区与失败日志，不更新基线，并在汇报中列出失败命令。

自动任务不自动 commit 或 push，除非用户明确要求。工作区已有未提交改动时，先识别
这些改动并保留，不得回退或覆盖。

## 手动检查

```bash
./scripts/check_upstream.sh
./scripts/verify_all.sh
```

上游克隆位于 `.research/upstream-mio`（被 `.gitignore` 忽略），仅作为比较基准，不参与
本项目的构建。