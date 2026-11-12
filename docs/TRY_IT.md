# 第一次试用 CertOps

第一次可以先查看界面、导入测试证书，熟悉版本和绑定关系，再接入一个有授权的测试目标。单纯启动控制台不需要填写云账号或 SSH 凭据。

## 1. 启动独立控制台

准备 Linux x86_64、支持 `up --wait` 的 Docker Compose / Buildx 和 Python 3.10+。建议至少预留 2 GB 内存。首次构建需要下载基础镜像和前后端依赖，实际耗时取决于网络与机器性能。

```bash
git clone https://github.com/tanxl0810-cyber/certops.git
cd certops
python3 ops/init.py
docker compose up -d --build --wait
docker compose ps
```

国内也可用 `git clone https://gitee.com/norman-tan/certops.git` 下载同一份开源源码，然后执行相同的启动步骤。

默认访问 <http://127.0.0.1:18090>。账号是 `admin`，在本机编辑器中打开 `.env` 查看 `ADMIN_PASSWORD`，首次登录按提示改密。请保留并备份 `ENCRYPTION_KEY`，不要反复初始化来替换密钥。

远程服务器的 SSH 隧道、HTTPS 和代理设置见 [DEPLOYMENT](DEPLOYMENT.md)。

## 2. 先认识几个页面

- **总览**：关注证书到期时间、目标实际状态和任务进度。
- **证书管理**：一条证书记录可保留多个版本，最新版本和历史版本分别记录。
- **证书与服务**：查看已保存绑定、自动更新范围，以及观测到的使用证据。
- **任务记录**：查看提交、等待生效、完成和失败情况。

新安装的数据库为空。README 中的截图使用虚构演示数据，不会自动出现在你的安装中。

## 3. 用测试证书体验版本管理（可选）

如果本机有 OpenSSL，可以在项目的 `private/` 目录生成仅用于本地导入演示的自签证书。请在尚不存在这两个演示文件的测试目录中执行：

```bash
mkdir -p private/try-cert
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 30 \
  -subj '/CN=demo.example.test' \
  -addext 'subjectAltName=DNS:demo.example.test' \
  -keyout private/try-cert/demo-key.pem \
  -out private/try-cert/demo-cert.pem
```

在「证书管理」新建证书，名称可填「本地试用」，域名填 `demo.example.test`。用本机编辑器打开 `demo-cert.pem` 和对应的 `demo-key.pem`，把内容分别填入上传窗口的证书 PEM、私钥 PEM 字段，再查看到期时间、指纹和历史版本。

`example.test` 是演示域名，自签证书不会获得浏览器的公共信任。此步骤仅用于体验导入与版本管理；真实业务部署应使用覆盖实际域名且满足目标产品要求的证书。`private/` 和密钥文件已在 Git 忽略范围内，也不要手动强制提交。

## 4. 再接入一个测试目标

选用自己拥有或已获授权的测试环境，先保持自动续签、自动部署关闭。

1. 为对应云产品或主机准备专用、限权的访问方式，参考 [ALIYUN](ALIYUN.md) 或 [YUNXIAO](YUNXIAO.md)。
2. 导入覆盖真实测试域名的证书，保存一个部署绑定，核对监听端口、证书槽位或 Nginx 文件路径。
3. 查看部署预览，确认版本和目标范围，再提交这一次测试更新。
4. 核对任务结果和实际 TLS 指纹，并演练支持的回退方式。
5. 验证通过后，再按需要开启自动化。阿里云签发需已有申请资源或额度。

备份、恢复和云端提交结果不明的处理见 [OPERATIONS](OPERATIONS.md)。

## 5. 把试用卡点反馈回来

可通过 [GitHub Issues](https://github.com/tanxl0810-cyber/certops/issues) 或 [Gitee Issues](https://gitee.com/norman-tan/certops/issues) 说明：安装环境、使用的产品、想完成的操作、卡住的步骤、脱敏错误信息和预期结果。

不要发送 AccessKey、私钥、会话 Cookie、完整 `.env` 或生产备份。疑似漏洞请按 [SECURITY](../SECURITY.md) 私密反馈。

需要停止试用环境时执行 `docker compose down`。该命令保留数据库卷，之后可再次启动。
