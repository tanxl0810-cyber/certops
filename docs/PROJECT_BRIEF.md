# CertOps 项目简介与分享文案

本页汇总可供项目目录、技术文章、社区分享和资料引用的事实信息。范围核对日期：2026-11-12。后续能力以对应版本的代码与文档为准。

## 项目摘要

| 项目 | 内容 |
| --- | --- |
| 名称 | CertOps · 证书部署与运维控制台 |
| 英文简介 | Self-hosted SSL/TLS certificate management and deployment for Alibaba Cloud and Nginx |
| GitHub | https://github.com/tanxl0810-cyber/certops |
| Gitee | https://gitee.com/norman-tan/certops |
| 许可证 | Apache-2.0，允许按许可证条款自行部署和商业使用 |
| 阶段 | 早期公开版本，适合可信运维团队先在测试环境验收 |
| 部署方式 | Docker Compose，独立 PostgreSQL，单 worker，无需 Redis |
| 主要用途 | 证书版本管理、证书与服务关联、影响预览、换证与实际 TLS 检查 |
| 证书申请 | 阿里云 SSL V1.0 已有资源包、V2.0 订阅实例；支持上传或导入已有证书 |
| 部署接入 | 已适配阿里云产品、SSH/SFTP / Nginx、云效流水线 |
| 登录与通知 | 本地管理员，可选飞书成员白名单登录与飞书通知 |
| 联系方式 | tanxl0810@gmail.com，微信名片见服务说明 |

## 适合解决的具体问题

- 同一张通配符证书分散在阿里云入口和机房 Nginx 上，更新时容易遗漏目标。
- 已经上传了新证书，需要知道哪些目标会更新、哪些入口仍在使用历史版本。
- 云 API 或流水线执行后，需要继续核对实际 TLS 指纹，并保留失败原因与操作记录。
- 想自己部署证书控制台，同时按需购买接入、改造或维护协助。

## 中文分享文案

我开源了 CertOps，一个面向阿里云和自建 Nginx 的 SSL/TLS 证书管理与部署控制台。它把证书版本、服务绑定、部署前影响预览和实际 TLS 检查放在一起，帮助核对一张证书会更新哪些入口、哪些服务还在用历史版本。

支持使用已有阿里云申请资源进行签发 / 续签，通过云 API、SSH 或云效流水线部署，提供 Docker Compose 独立安装和演示截图。采用 Apache-2.0 许可证，可免费自行部署，也提供可选的部署与定制协助。

目前是早期公开版本，欢迎有阿里云或 Nginx 证书维护需求的运维同学在测试环境试用，并反馈安装、单目标换证和恢复过程中的卡点。当前没有通用 ACME / Let's Encrypt 申请适配器、租户隔离或细粒度 RBAC。

代码与截图：https://github.com/tanxl0810-cyber/certops

国内镜像：https://gitee.com/norman-tan/certops

首次试用：[TRY_IT](TRY_IT.md) · 能力与限制：[FAQ](FAQ.md) · 联系与服务：[SERVICES](../SERVICES.md)

## English summary

CertOps is an early public, Apache-2.0-licensed, self-hosted SSL/TLS certificate operations console for trusted teams managing Alibaba Cloud services and Nginx hosts. It combines certificate version history, saved deployment bindings, deployment previews, persistent task progress, and observed TLS fingerprints. It supports existing Alibaba Cloud SSL application resources, cloud product APIs, SSH/SFTP, and Yunxiao pipelines. A Docker Compose installation includes its own PostgreSQL database and a single worker.

There is no general-purpose ACME / Let's Encrypt issuance adapter, tenant isolation, or fine-grained RBAC. Production use requires acceptance checks for the specific account, product configuration, and target. See the [English README](../README.en.md) for setup and scope.
