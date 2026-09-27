# 数字凭证签发、验证和撤销服务

标准库 Python 3.11+ 实现，使用 SQLite 保存密钥版本、模板、凭证、争议、密钥事故和审计记录。服务支持最少字段披露、离线签名的在线撤销复核、密钥轮换、证件状态争议和密钥版本泄露事故处置。

代码按职责分为三个业务文件：

- `storage.py`：档案保存——SQLite 表结构、连接与审计日志。
- `incidents.py`：事故判定——事故登记、更正/撤回与核验期生效判定。
- `app.py`：请求入口——HTTP 路由与签发、撤销、争议、核验等凭证业务。

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
- `POST /api/incidents`：签发方登记密钥版本泄露事故，字段 `key_version`、`description`，可选 `discovered_at`、`effective_at`（默认当前时间，生效时间不得早于发现时间）。同一密钥版本只允许一个未关闭事故，返回事故编号 `INC-xxxx`。
- `POST /api/incidents/{id}/correct`、`POST /api/incidents/{id}/withdraw`：更正或撤回事故，需提供 `resolution`。
- `GET /api/state`、`GET /api/health`：查看状态和健康检查。

## 密钥版本事故处置

签发方密钥版本泄露后，登记事故并指定发现时间、生效时间和说明。事故生效后，**在线核验**该密钥版本签出的凭证一律返回 `valid=false`、`status=unavailable` 并附带 `incident_no`；其它密钥版本签出的凭证不受影响；事故生效前或离线核验不拦截（离线结果仍提示需要在线检查）。

事故更正或撤回后不再覆盖核验结果，受影响凭证重新按撤销、争议和有效期判定。事故期间凭证记录本身不被修改，原独立撤销记录完整保留；事故关闭后同一密钥版本可以再次登记新事故。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

这是本地原型：私钥保存在 SQLite 中，离线验证只能依赖令牌内的到期时间，真实撤销仍需在线检查；也未实现可验证凭证联盟标准或硬件密钥保护。
