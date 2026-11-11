# 可选飞书登录

默认只启用本地管理员登录。飞书接入使用本项目独立配置的企业标识和成员 OpenID 白名单，不需要其他业务系统或成员数据库。

## 配置

1. 使用自己的企业自建应用，按飞书平台要求配置应用可用范围、身份信息权限及发布状态。
2. 为控制台配置有效的 HTTPS 域名，例如 `https://cert.example.com`。
3. 在飞书应用的重定向 URL 中登记 `https://cert.example.com/api/auth/feishu/callback`。
4. 在本机 `.env` 填写以下变量，实际值不要提交到 Git：

```dotenv
PUBLIC_URL=https://cert.example.com
FEISHU_APP_ID=YOUR_APP_ID
FEISHU_APP_SECRET=YOUR_APP_SECRET
FEISHU_TENANT_KEY=YOUR_TENANT_KEY
FEISHU_ALLOWED_OPEN_IDS=ou_member_one,ou_member_two
```

白名单必须使用该应用下的成员 **OpenID**，不能使用 user_id、union_id 或其他应用下的 OpenID。请通过飞书应用自己的授权管理或受控调试渠道确认，避免在公开问题中暴露成员标识。

重建 web 使配置生效：

```bash
docker compose up -d --force-recreate web
```

## 行为和权限

四项飞书配置不完整、成员白名单为空或入口不是 HTTPS 时，飞书入口保持关闭。本地管理员仍可使用。

登录使用 OAuth v2、PKCE S256、浏览器绑定 state、五分钟有效期和数据库单次消费。系统校验企业标识及白名单，不持久化飞书访问令牌。

每次认证请求重新核对白名单。修改 `.env` 不会自动更新现有容器；从白名单移除成员并重建 web 后，该成员后续请求失效。关闭飞书配置也会使已有飞书会话失效。本地管理员不受白名单影响。

**所有允许登录的成员均有完整管理权限。**当前没有部门、角色或证书分组隔离。需要细粒度授权时，请先实现并验证相应权限能力。

飞书机器人通知在控制台的访问凭据中另行配置，与登录应用无关；不会因为启用飞书登录而自动发送通知。
