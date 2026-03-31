# 发布指南

## 构建 WASM 包

### 1. 构建 WASM 模块

```bash
# 构建 release 版本
cargo build --lib --target wasm32-unknown-unknown --release

# 生成 JS 绑定
wasm-bindgen %CARGO_TARGET%\wasm32-unknown-unknown\release\kdbx_rs.wasm \
  --out-dir js \
  --target web \
  --no-typescript

# 或使用优化（需要 wasm-opt）
wasm-opt -Os js\kdbx_rs_bg.wasm -o js\kdbx_rs_bg.wasm
```

### 2. 测试包

```bash
cd js
npm pack --dry-run
```

### 3. 发布到 NPM

```bash
# 登录 NPM（如果未登录）
npm login

# 发布包
cd js
npm publish --access public
```

## 创建 GitHub 仓库并推送

### 1. 创建仓库

访问 https://github.com/new 创建新仓库，命名为 `kdbx-wasm`

### 2. 推送代码

```bash
# 初始化 git（如果未初始化）
git init

# 添加远程仓库
git remote add origin https://github.com/yzbtdiy/kdbx-wasm.git

# 添加文件
git add .
git commit -m "Initial release: WASM-based KDBX parser"

# 推送
git push -u origin main
```

### 3. 创建 Release

访问 GitHub 仓库页面，点击 "Releases" -> "Create a new release"

- Tag: v0.1.0
- Title: v0.1.0 - Initial Release
- Description: 添加发布说明

## 文件说明

### JS 包文件 (js/)

| 文件 | 大小 | 说明 |
|------|------|------|
| kdbx_rs_bg.wasm | ~421 KB | WASM 模块 |
| kdbx_rs.js | ~18 KB | WASM 绑定代码 |
| index.js | ~0.5 KB | 主入口 |
| index.d.ts | ~4 KB | TypeScript 类型定义 |
| package.json | ~1 KB | NPM 配置 |
| README.md | ~4 KB | 文档 |
| LICENSE | ~1 KB | MIT 许可证 |

**打包后大小**: ~189 KB (gzip 后更小)

## 使用方式

### 浏览器

```html
<script type="module">
  import { KdbxDatabase } from 'https://unpkg.com/kdbx-wasm@0.1.0/index.js';
  
  const db = new KdbxDatabase(fileData, 'password');
  const entries = db.getEntries();
</script>
```

### Node.js

```bash
npm install kdbx-wasm
```

```javascript
import { KdbxDatabase } from 'kdbx-wasm';
```

## 版本更新

更新版本时：

1. 更新 `Cargo.toml` 中的版本号
2. 更新 `js/package.json` 中的版本号
3. 重新构建 WASM
4. 发布到 NPM
5. 创建 GitHub Release

```bash
# 更新版本
npm version patch  # 或 minor, major

# 发布
npm publish
```
