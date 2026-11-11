# 独立部署

## 环境

推荐 Linux x86_64，Docker Engine 及 Compose / Buildx 插件（Compose 需支持 `up --wait`）、Python 3.10+。Windows / macOS 可使用 Docker Desktop；初始化命令中的 `python3` 可按本机情况改为 `python`。完整镜像构建和主机脚本以 Linux 为目标。

首次构建需要访问 Docker Hub、npm 和 PyPI；运行时需要访问实际使用的云 API、DNS 服务、目标 TLS 或 SSH 入口。云效部署还要求目标机能够访问控制台的 HTTPS 入口。

数据库由 Compose 独立创建，使用持久化卷 `postgres_data`。数据库管理员与应用数据库账号分离，应用账号不具有超级用户、建库或建角色权限。web 与 worker 通过专用内部网络访问数据库；无需已有数据库或其他业务系统。

## 本地或首次试用

```bash
python3 ops/init.py
docker compose up -d --build --wait
docker compose ps
```

初始化脚本从安全随机源生成两个数据库密码、Fernet 主密钥和初始管理员密码，并保存到 `.env`。Unix 下文件创建权限为 0600；Windows 下请另外检查文件 ACL，确保仅管理人员可读。不要将 `.env` 粘贴到工单或日志。

访问 <http://127.0.0.1:18090>，使用 `admin` 及 `.env` 中的 `ADMIN_PASSWORD` 登录并改密。首次改密只更新管理员口令，不改变加密主密钥。

使用其他本机端口：

```bash
python3 ops/init.py --port 18091
```

若 `.env` 已存在，脚本拒绝覆盖；请直接修改其中的 `HTTP_PORT` 与 `PUBLIC_URL`，保留原密码和主密钥。

## 正式域名与 HTTPS

以下全部为示例；把 `cert.example.com` 替换为你自己的域名。

```bash
python3 ops/init.py --public-url https://cert.example.com
docker compose up -d --build --wait
```

在宿主机 Nginx 配置 HTTPS 入口，参考 [nginx.conf.example](../deploy/nginx.conf.example)，填写自己的服务域名、入口证书和私钥路径，确认 `proxy_pass` 指向本机 18090 端口。先执行 `nginx -t`，通过后再重载。

已有 `.env` 时将 `PUBLIC_URL` 改为最终 HTTPS origin，然后执行：

```bash
docker compose up -d --force-recreate web worker
```

`PUBLIC_URL` 不包含路径或末尾斜杠，必须与浏览器地址一致，否则 Origin/CSRF 校验会拒绝写操作。保留原始 `Host`，入口代理对 OAuth 回调关闭包含查询参数的访问日志。

`FORWARDED_ALLOW_IPS` 只填写可信反向代理连接到容器时的实际来源 IP。宿主机 Nginx 经 Docker 发布端口接入时，该来源可能是 Docker 网桥网关，应根据实际网络核对后配置；默认值只信任回环地址。无需为了 HTTPS Cookie 而信任所有来源，应用同时依据规范的 `PUBLIC_URL` 与 Host 设置安全 Cookie。错误代理信任配置会影响真实客户端 IP 及登录限速。

默认 `BIND_ADDRESS=127.0.0.1`。如果入口代理不在同一主机，需按实际拓扑设置绑定地址和访问控制，仅允许可信代理访问。不要公开 PostgreSQL 端口。

## 配置项

| 变量 | 用途 |
| --- | --- |
| `PUBLIC_URL` | 唯一浏览器入口 origin，飞书启用时必须为 HTTPS |
| `BIND_ADDRESS` / `HTTP_PORT` | 宿主机管理入口绑定地址与端口 |
| `POSTGRES_PASSWORD` | 独立 PostgreSQL 管理员密码，仅 db 容器使用 |
| `DATABASE_PASSWORD` | 非超级用户 `certops` 的数据库密码 |
| `ENCRYPTION_KEY` | Fernet 主密钥；必须独立备份、长期保留 |
| `ADMIN_PASSWORD` | 空库首次创建本地管理员时使用，至少 16 字符 |
| `FORWARDED_ALLOW_IPS` | Uvicorn 信任代理头的来源 IP 列表 |
| `TZ` | 默认时区，默认 `Asia/Shanghai` |
| `FEISHU_*` | 可选登录配置，见 [FEISHU](FEISHU.md) |

应用代码还支持直接设置 `DATABASE_URL`、`ADMIN_PASSWORD_FILE`；默认 Compose 使用 `DATABASE_PASSWORD` 构造连接串，并从环境传入初始管理员密码。显式设置 `ADMIN_PASSWORD_FILE` 时，文件优先于 `ADMIN_PASSWORD`。

**初始化 SQL 仅在数据库数据卷为空时执行。**修改 `.env` 中的数据库密码不会修改已有数据库角色口令；轮换需同时修改 PostgreSQL 中的对应角色，再更新配置并重建应用。重新生成 `ENCRYPTION_KEY` 不会重新加密旧数据，也不能恢复旧凭据。

## 健康检查和升级

```bash
docker compose ps
docker compose logs --tail=80 web worker
curl --fail http://127.0.0.1:18090/healthz
```

升级前查看变更说明，停止 worker，备份数据库并保留当前版本源码及配置：

```bash
docker compose stop worker
python3 ops/backup.py
docker compose build web
docker compose up -d --wait
```

数据库结构存在不兼容变化时，应按该版本的迁移说明处理；当前没有完整的版本化迁移系统。不要仅切换旧镜像就认为数据已经回退。恢复过程见 [OPERATIONS](OPERATIONS.md)。

## 常见问题

- 登录提示来源不受信任：核对浏览器地址、`PUBLIC_URL`、端口和代理 Host。
- web 启动失败：核对 `.env` 是否为初始化脚本生成的实际配置、数据库是否健康、首次密码是否至少 16 字符。
- 首次创建角色失败后重启仍报错：数据库卷可能已经部分初始化，应先检查日志和角色状态。确认是可丢弃的新测试环境后才可重建数据卷；已有数据环境不得通过删除卷修复。
- 没有样式或静态文件：使用完整多阶段 Docker 构建；本地开发需先构建前端。
- SSH 接入失败：核对可信主机指纹、账号权限、跳板链及 Nginx 命令。云效方式见 [YUNXIAO](YUNXIAO.md)。
