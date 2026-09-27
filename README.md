# 数字凭证签发、验证和撤销服务

标准库 Python 3.11+ 实现，使用 SQLite 保存密钥版本、模板、凭证、争议、密钥事故和审计记录。服务支持最少字段披露、离线签名的在线撤销复核、密钥轮换、证件状态争议和密钥版本事故处置。

代码按职责分三个业务文件：`app.py` 为请求入口（HTTP 路由与启动），`service.py` 负责业务与事故判定，`store.py` 负责档案保存（SQLite）。

## 初始化与启动

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8211`，也可使用 `--port` 与 `--db` 覆盖端口和数据库路径。身份使用 `X-Actor`、`X-Role` 请求头，角色为 `issuer`、`holder` 或 `regulator`。

## 主要接口

- `POST /api/keys/rotate`：签发方轮换密钥。
- `POST /api/templates`：创建凭证模板。
- `POST /api/credentials`：签发凭证，支持幂等键。
- `POST /api/credentials/{id}/present`：按持有人选择披露字段并生成令牌。
- `POST /api/verify`：验证令牌，可指定验证时间与在线/离线模式。
- `POST /api/credentials/{id}/revoke`：签发方撤销凭证。
- `POST /api/credentials/{id}/dispute`、`POST /api/disputes/{id}/resolve`：提出和处理撤销争议。
- `POST /api/incidents`：签发方登记密钥版本事故，需提交 `key_version`、`discovered_at`（发现时间）、`effective_at`（生效时间）和 `reason`（说明）；同一密钥版本只允许一个未关闭事故。
- `POST /api/incidents/{id}/close`：以 `action=correct`（更正）或 `withdraw`（撤回）关闭事故。
- `GET /api/state`、`GET /api/health`：查看状态和健康检查。

## 密钥事故处置

密钥版本泄露后，签发方登记事故。事故生效时间之后，在线核验该版本签出的凭证返回 `status=unavailable` 并携带 `incident_id`（事故编号），其他密钥版本签出的凭证不受影响；生效时间点之前仍按原规则判定。事故只影响核验判定，不改写凭证记录。事故更正或撤回后，受影响凭证恢复按撤销、争议和有效期重新判定，原有独立撤销记录保留。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

这是本地原型：私钥保存在 SQLite 中，离线验证只能依赖令牌内的到期时间，真实撤销仍需在线检查；也未实现可验证凭证联盟标准或硬件密钥保护。
