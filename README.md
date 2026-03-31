# kdbx-wasm

一个使用 Rust 和 WebAssembly 构建的高性能 KDBX 密码数据库解析器，支持 KDBX 4 格式。

## 功能特性

- **完整的 KDBX 4 支持**：解析、修改和生成 KDBX 4 格式文件
- **多种加密算法**：AES-256-CBC 和 ChaCha20
- **密钥派生函数**：Argon2d、Argon2id 和 AES-KDF
- **WebAssembly 驱动**：基于 Rust 实现，通过 WASM 在浏览器中运行
- **TypeScript 支持**：完整的类型定义
- **安全优先**：安全内存容器，敏感数据自动清零

## 快速开始

### 浏览器中使用

```html
<!DOCTYPE html>
<html>
<head>
  <script type="module">
    import { KdbxDatabase, isKdbxFile } from 'kdbx-wasm';
    
    // 加载 KDBX 文件
    const response = await fetch('passwords.kdbx');
    const fileData = new Uint8Array(await response.arrayBuffer());
    
    // 检查是否为有效的 KDBX 文件
    if (isKdbxFile(fileData)) {
      console.log('有效的 KDBX 文件!');
    }
    
    // 打开数据库
    const db = new KdbxDatabase(fileData, 'master-password');
    
    // 获取所有条目
    const entries = db.getEntries();
    entries.forEach(entry => {
      console.log(`标题: ${entry.title}`);
      console.log(`用户名: ${entry.username}`);
      console.log(`密码: ${entry.password}`);
    });
  </script>
</head>
<body>
  <h1>KDBX Parser Demo</h1>
</body>
</html>
```

### API 参考

#### `KdbxDatabase` 类

**构造函数**
```javascript
new KdbxDatabase(data: Uint8Array, password?: string, keyFile?: Uint8Array)
```

**属性**
- `metadata`: 数据库元数据（名称、描述等）
- `headerInfo`: 头部信息（加密算法、KDF、条目数等）
- `rootGroupUuid`: 根组 UUID

**方法**
- `getEntries()`: 获取所有条目
- `getEntry(uuid: string)`: 根据 UUID 获取条目
- `getGroups()`: 获取所有组
- `getGroup(uuid: string)`: 根据 UUID 获取组
- `getEntriesByGroup(groupUuid: string)`: 获取指定组的所有条目
- `searchEntries(query: string)`: 搜索条目
- `toBytes(password?: string, keyFile?: Uint8Array)`: 导出为 KDBX 字节

#### 工具函数

- `isKdbxFile(data: Uint8Array): boolean`: 检查数据是否为有效的 KDBX 文件
- `getFileInfo(data: Uint8Array): object`: 无需解密获取文件信息

## 项目结构

```
.
├── Cargo.toml          # Rust 项目配置
├── src/
│   ├── lib.rs          # 库入口
│   ├── wasm.rs         # WASM 绑定
│   ├── core/           # 核心解析逻辑
│   │   ├── parser/     # KDBX 解析器
│   │   ├── crypto/     # 加密实现
│   │   └── types/      # 数据类型
│   ├── api/            # REST API (非 WASM)
│   └── service/        # 业务服务 (非 WASM)
├── js/                 # JavaScript 包装
│   ├── index.js        # 主入口
│   ├── index.d.ts      # TypeScript 类型定义
│   ├── kdbx_rs.js      # WASM 生成的 JS 绑定
│   ├── kdbx_rs_bg.wasm # WASM 模块
│   ├── example.html    # 浏览器示例
│   └── README.md       # JS 库文档
└── build-wasm.bat      # 构建脚本
```

## 构建

### 前提条件

- Rust 1.94.0 或更高版本
- wasm-bindgen-cli

### 构建 WASM 模块

```bash
# 安装 wasm-bindgen-cli
cargo install wasm-bindgen-cli

# 运行构建脚本
.\build-wasm.bat
```

或者手动构建：

```bash
# 构建 WASM 模块
cargo build --lib --target wasm32-unknown-unknown --release

# 生成 JS 绑定
wasm-bindgen target\wasm32-unknown-unknown\release\kdbx_rs.wasm \
  --out-dir js \
  --target web \
  --no-typescript
```

## 运行示例

```bash
# 启动本地服务器
cd js
python -m http.server 8080

# 打开浏览器访问 http://localhost:8080/example.html
```

## 服务器模式（非 WASM）

除了 WASM 库，本项目还包含一个完整的 REST API 服务器：

```bash
# 运行服务器
cargo run --release

# 服务器将在 http://localhost:3000 启动
```

查看 [API 文档](docs/API.md) 了解更多详情。

## 浏览器兼容性

- Chrome 57+
- Firefox 52+
- Safari 11+
- Edge 16+

## 安全注意事项

- 主密码用于派生加密密钥
- 密钥文件可以与密码一起使用或单独使用
- 所有加密操作都在 WebAssembly 中执行
- 敏感数据在可能的情况下从内存中清除

## 技术栈

| 组件 | 技术 | 版本 |
|------|------|------|
| 编程语言 | Rust | 1.94.0 |
| WASM 绑定 | wasm-bindgen | 0.2.100 |
| 加密 | RustCrypto | 最新版 |
| XML 解析 | roxmltree | 0.20.0 |
| 压缩 | flate2 | 1.1.9 |

## 许可证

MIT License

## 致谢

- [KeePass](https://keepass.info/) - KDBX 文件格式规范
- [RustCrypto](https://github.com/RustCrypto) - 纯 Rust 加密实现
- [wasm-bindgen](https://github.com/rustwasm/wasm-bindgen) - Rust 与 WebAssembly 的桥梁
