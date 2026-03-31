# KDBX Server API 文档

## 概述

KDBX Server 提供用于管理 KeePass KDBX 4 密码数据库文件的 RESTful API。

**基础 URL**: `http://localhost:3000`

**Content-Type**: `application/json`（除非另有说明）

## 认证

API 不实现用户认证。每个会话由 UUID 标识，会话在默认 30 分钟不活动后过期。

## 错误响应

所有错误响应遵循以下格式：

```json
{
  "error": {
    "code": "错误代码",
    "message": "人类可读的错误消息",
    "details": {}
  }
}
```

### 常见错误代码

| 代码 | HTTP 状态 | 描述 |
|------|-----------|------|
| `INVALID_FILE_FORMAT` | 400 | 上传的文件不是有效的 KDBX 4 文件 |
| `INVALID_SIGNATURE` | 400 | 文件签名验证失败 |
| `UNSUPPORTED_VERSION` | 400 | 文件版本不是 KDBX 4.x |
| `INVALID_MASTER_KEY` | 401 | 主密码错误 |
| `SESSION_NOT_FOUND` | 404 | 会话 ID 不存在 |
| `SESSION_EXPIRED` | 410 | 会话已过期 |
| `ENTRY_NOT_FOUND` | 404 | 条目 ID 不存在 |
| `GROUP_NOT_FOUND` | 404 | 分组 ID 不存在 |
| `VALIDATION_ERROR` | 400 | 请求验证失败 |

---

## 端点

### 健康检查

#### GET /health

检查服务器健康状态。

**响应**:
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime_seconds": 3600
}
```

---

### 会话管理

#### POST /api/v1/sessions

通过上传 KDBX 文件创建新会话。

**请求**:
- Content-Type: `multipart/form-data`
- 字段:
  - `file` (必需): KDBX 文件
  - `master_password` (可选): 主密码
  - `key_file` (可选): 密钥文件

**响应** (201 Created):
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "metadata": {
    "version": "4.0",
    "encryption_algorithm": "Aes256",
    "kdf": "Argon2id",
    "entry_count": 42,
    "group_count": 5
  },
  "created_at": "2024-01-01T00:00:00Z"
}
```

#### GET /api/v1/sessions/{id}

获取会话信息。

**响应** (200 OK):
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "metadata": {
    "version": "4.0",
    "encryption_algorithm": "Aes256",
    "kdf": "Argon2id",
    "entry_count": 42,
    "group_count": 5
  },
  "created_at": "2024-01-01T00:00:00Z"
}
```

#### DELETE /api/v1/sessions/{id}

关闭会话并清除敏感数据。

**响应**: 204 No Content

---

### 条目管理

#### POST /api/v1/sessions/{sid}/entries

创建新的密码条目。

**请求体**:
```json
{
  "title": "Google 账户",
  "username": "user@example.com",
  "password": "secret123",
  "url": "https://accounts.google.com",
  "notes": "个人账户",
  "tags": ["work", "mail"],
  "custom_fields": {
    "OTP": "otpauth://totp/example"
  },
  "icon_id": 15,
  "group_id": "550e8400-e29b-41d4-a716-446655440001",
  "expires_at": "2025-01-01T00:00:00Z"
}
```

**必填字段**:
- `title`: 条目标题（最多 500 字符）
- `password`: 密码（最多 10000 字符）

**可选字段**:
- `username`: 用户名（最多 500 字符）
- `url`: URL（最多 2000 字符）
- `notes`: 备注（最多 10000 字符）
- `tags`: 标记列表
- `custom_fields`: 自定义字段键值对
- `icon_id`: 图标 ID（0-99）
- `group_id`: 父分组 UUID
- `expires_at`: 过期时间戳

**响应** (201 Created):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440002",
  "title": "Google 账户",
  "username": "user@example.com",
  "password": "secret123",
  "url": "https://accounts.google.com",
  "notes": "个人账户",
  "tags": ["work", "mail"],
  "custom_fields": {
    "OTP": "otpauth://totp/example"
  },
  "icon_id": 15,
  "group_id": "550e8400-e29b-41d4-a716-446655440001",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z",
  "accessed_at": "2024-01-01T00:00:00Z",
  "expires_at": "2025-01-01T00:00:00Z"
}
```

#### GET /api/v1/sessions/{sid}/entries

列出条目，支持过滤和分页。

**查询参数**:
- `page`: 页码（默认: 1）
- `per_page`: 每页数量（默认: 20，最大: 100）
- `search`: 搜索关键词（搜索标题、用户名、URL）
- `group_id`: 按分组 UUID 过滤

**响应** (200 OK):
```json
{
  "entries": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440002",
      "title": "Google 账户",
      "username": "user@example.com",
      "password": "secret123",
      "url": "https://accounts.google.com",
      "notes": "个人账户",
      "tags": ["work", "mail"],
      "custom_fields": {
        "OTP": "otpauth://totp/example"
      },
      "icon_id": 15,
      "group_id": "550e8400-e29b-41d4-a716-446655440001",
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z",
      "accessed_at": "2024-01-01T00:05:00Z",
      "expires_at": "2025-01-01T00:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 42,
    "total_pages": 3
  }
}
```

#### GET /api/v1/sessions/{sid}/entries/{eid}

获取条目详情，包括密码。

**响应** (200 OK):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440002",
  "title": "Google 账户",
  "username": "user@example.com",
  "password": "secret123",
  "url": "https://accounts.google.com",
  "notes": "个人账户",
  "tags": ["work", "mail"],
  "custom_fields": {
    "OTP": "otpauth://totp/example"
  },
  "icon_id": 15,
  "group_id": "550e8400-e29b-41d4-a716-446655440001",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z",
  "accessed_at": "2024-01-01T00:05:00Z",
  "expires_at": "2025-01-01T00:00:00Z"
}
```

#### PATCH /api/v1/sessions/{sid}/entries/{eid}

更新条目字段（部分更新）。

**请求体**:
```json
{
  "tags": ["work", "mail"],
  "custom_fields": {
    "OTP": "otpauth://totp/example"
  },
  "password": "newsecret456",
  "notes": "更新备注"
}
```

**响应** (200 OK): 返回更新后的条目

#### DELETE /api/v1/sessions/{sid}/entries/{eid}

删除条目（默认软删除）。

**响应**: 204 No Content

---

### 分组管理

#### POST /api/v1/sessions/{sid}/groups

创建新分组。

**请求体**:
```json
{
  "name": "社交媒体",
  "parent_id": "550e8400-e29b-41d4-a716-446655440001",
  "icon_id": 25
}
```

**必填字段**:
- `name`: 分组名称（最多 500 字符）

**可选字段**:
- `parent_id`: 父分组 UUID
- `icon_id`: 图标 ID（0-99）

**响应** (201 Created):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440003",
  "name": "社交媒体",
  "parent_id": "550e8400-e29b-41d4-a716-446655440001",
  "icon_id": 25,
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
```

#### GET /api/v1/sessions/{sid}/groups/tree

获取分组树结构。

**响应** (200 OK):
```json
{
  "groups": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "name": "根",
      "icon_id": 0,
      "children": [
        {
          "id": "550e8400-e29b-41d4-a716-446655440003",
          "name": "社交媒体",
          "icon_id": 25,
          "children": []
        }
      ]
    }
  ]
}
```

#### PATCH /api/v1/sessions/{sid}/groups/{gid}

更新分组字段。

**请求体**:
```json
{
  "name": "更新名称"
}
```

**响应** (200 OK): 返回更新后的分组

#### DELETE /api/v1/sessions/{sid}/groups/{gid}

删除分组（必须为空，除非 force=true）。

**响应**: 204 No Content

---

### 文件导出

#### GET /api/v1/sessions/{id}/export

导出修改后的 KDBX 文件。

**查询参数**:
- `encryption`: 加密算法（`aes256` 或 `chacha20`）
- `compression`: 启用压缩（`true` 或 `false`）

**响应**:
- Content-Type: `application/octet-stream`
- Content-Disposition: `attachment; filename="database.kdbx"`
- Body: 二进制 KDBX 文件

---

## 速率限制

当前未实现。将在未来版本中添加。

## CORS

默认为所有来源启用 CORS。在生产环境中请在 `config.toml` 中配置。

## 版本控制

API 使用 URL 路径版本控制（例如 `/api/v1/`）。破坏性更改将导致新版本号。

## 示例

### 完整工作流程

```bash
# 1. 上传 KDBX 文件
SESSION_ID=$(curl -s -X POST http://localhost:3000/api/v1/sessions \
  -F "file=@database.kdbx" \
  -F "master_password=mypassword" | jq -r '.session_id')

# 2. 列出条目
curl -s "http://localhost:3000/api/v1/sessions/$SESSION_ID/entries" | jq .

# 3. 创建新条目
curl -s -X POST "http://localhost:3000/api/v1/sessions/$SESSION_ID/entries" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "新网站",
    "username": "user@example.com",
    "password": "secret123",
    "url": "https://example.com"
  }' | jq .

# 4. 导出修改后的数据库
curl -o modified.kdbx "http://localhost:3000/api/v1/sessions/$SESSION_ID/export"

# 5. 关闭会话
curl -X DELETE "http://localhost:3000/api/v1/sessions/$SESSION_ID"
```

## 字段验证规则

### 条目字段

| 字段 | 必填 | 最大长度 | 说明 |
|------|------|----------|------|
| title | 是 | 500 | 条目标题，不能仅包含空白字符 |
| password | 是 | 10000 | 密码 |
| username | 否 | 500 | 用户名 |
| url | 否 | 2000 | URL，需包含协议头 |
| notes | 否 | 10000 | 备注 |
| icon_id | 否 | - | 图标 ID，范围 0-99 |
| group_id | 否 | - | 父分组 UUID |
| expires_at | 否 | - | 过期时间，UTC 时间戳 |

### 分组字段

| 字段 | 必填 | 最大长度 | 说明 |
|------|------|----------|------|
| name | 是 | 500 | 分组名称，不能仅包含空白字符 |
| parent_id | 否 | - | 父分组 UUID，必须引用已存在的分组 |
| icon_id | 否 | - | 图标 ID，范围 0-99 |

## 时间格式

所有时间戳使用 ISO 8601 格式（RFC 3339）：
- 格式：`YYYY-MM-DDTHH:MM:SSZ`
- 示例：`2024-01-01T00:00:00Z`
- 时区：UTC

## UUID 格式

所有 ID 使用 UUID v4 格式：
- 格式：`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- 示例：`550e8400-e29b-41d4-a716-446655440000`

## 最佳实践

1. **会话管理**：
   - 使用完会话后及时关闭
   - 不要长时间保持会话打开
   - 定期检查会话是否过期

2. **错误处理**：
   - 始终检查 HTTP 状态码
   - 解析错误响应以获取详细信息
   - 实现重试逻辑处理临时错误

3. **安全建议**：
   - 使用 HTTPS 传输
   - 不要在客户端存储主密码
   - 定期更换密码
   - 使用强密码

4. **性能优化**：
   - 使用分页避免一次加载过多数据
   - 缓存会话 ID
   - 批量操作时使用异步请求
