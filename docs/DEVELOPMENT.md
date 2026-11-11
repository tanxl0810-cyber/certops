# 开发与验证

## 依赖与前端

推荐 Python 3.12、Node.js 22.12+ 与 Linux / WSL；系统需安装 Python venv 支持。本机依赖均在虚拟环境中安装。

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
npm --prefix ui ci
npm --prefix ui run build
```

前端产物输出到 `app/static/`，该目录不提交到 Git。Dockerfile 在多阶段构建中生成它，因此新克隆不依赖旧的编译文件。

## 自动化测试

```bash
python -m unittest discover -s tests -t . -v
python ops/test-pipeline-client.py
python ops/check-release.py
```

默认测试使用临时 SQLite，测试初始化密码、密钥和证书由测试创建，不读取部署 `.env`，不连接云 API 或真实 SSH 主机。Linux 客户端测试需要 OpenSSL，在临时目录模拟 Nginx 命令并验证回退。

涉及事务锁、并发导入、任务恢复和数据库约束的行为，还需要 PostgreSQL 验证。指定一个专用开发数据库：

```bash
export CERTOPS_DEV_DATABASE_URL='postgresql+psycopg://dev_user:dev_password@127.0.0.1:5432/certops_dev'
python ops/test-postgres.py
```

测试 runner 为每次执行创建随机 schema，通过 `search_path` 隔离并在结束后清理。仍然必须使用专用开发数据库，不能提供生产连接串。

也可在**本地独立 Compose 安装**中运行，勿指向生产目录：

```bash
docker compose run --rm --no-deps -v "$PWD/tests:/app/tests:ro" -v "$PWD/ops:/app/ops:ro" web sh -c 'CERTOPS_DEV_DATABASE_URL="$DATABASE_URL" python ops/test-postgres.py'
```

## 本地调试

在新的开发目录执行 `python ops/init.py`。Linux / WSL 下可读取自己生成的 `.env` 并显式选用本地 SQLite：

```bash
set -a
. ./.env
set +a
export DATABASE_URL=sqlite:///./certops-dev.db
python -m uvicorn app.main:app --host 127.0.0.1 --port 18090
```

这里的 `.env` 是自己生成的配置，不应加载来源不明的 shell 文件或生产配置。另一个终端需要相同的环境配置才能运行 `python -m app.worker`。SQLite 用于开发演示，正式部署与并发验收使用 PostgreSQL。

## CI 与发布

GitHub Actions 提供前端构建、Python 测试、发布文件检查、Gitleaks Git 历史扫描，以及独立 Compose 的构建、健康检查和 PostgreSQL 隔离测试。Actions 引用固定提交，扫描器下载校验固定 SHA-256。首次上传后以实际 Actions 结果为准。

运行 `python ops/package-release.py` 可生成只包含公开源文件的 ZIP，默认保存到 `dist/`。`.env`、Git 元数据、依赖目录、数据库、备份与编译产物不会进入归档。打包前仍需人工检查示例、截图和新增文件。

`docs/images/` 中已人工核对的演示 PNG、系统示意图和授权公开的微信名片使用明确文件名白名单进入归档；任意其他图片仍被排除。检查器拒绝 PNG 中的文本、EXIF 等附加元数据，JPEG 联系名片通过已核对文件的 SHA-256 校验。图片内文字需要人工确认；更新图片时同步核对 [图片说明](images/README.md)。

可另外使用 Gitleaks 扫描当前目录与 Git 历史：

```bash
gitleaks dir . --redact
gitleaks git . --redact
```

内置检查和通用扫描器都不能证明不存在所有敏感信息。发现真实凭据后先撤销/轮换，再处理文件及历史。
