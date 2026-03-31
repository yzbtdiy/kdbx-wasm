# 发布检查清单

## ✅ 构建完成

### WASM 模块
- [x] Release 构建成功
- [x] WASM 大小优化: 503 KB → 421 KB
- [x] JS 绑定生成成功

### NPM 包
- [x] 包大小: 189 KB (压缩后)
- [x] 包含所有必要文件
- [x] TypeScript 类型定义
- [x] 文档和许可证

## 📦 文件清单

```
kdbx-wasm-0.1.1.tgz (189 KB)
├── index.js          # 主入口
├── index.d.ts        # TypeScript 类型
├── kdbx_rs.js        # WASM 绑定 (18 KB)
├── kdbx_rs_bg.wasm   # WASM 模块 (421 KB)
├── package.json      # NPM 配置
├── README.md         # 文档
└── LICENSE           # MIT 许可证
```

## 🚀 发布步骤

### 1. 发布到 NPM
```bash
cd js
npm login
npm publish --access public
```

### 2. 创建 GitHub 仓库
```bash
git remote add origin https://github.com/yzbtdiy/kdbx-wasm.git
git push -u origin main
```

### 3. 创建 Release
- 访问: https://github.com/yzbtdiy/kdbx-wasm/releases
- 创建新 Release: v0.1.1

## 📖 使用示例

### 浏览器
```html
<script type="module">
  import { KdbxDatabase } from 'https://unpkg.com/kdbx-wasm@0.1.1/index.js';
  
  const response = await fetch('passwords.kdbx');
  const data = new Uint8Array(await response.arrayBuffer());
  const db = new KdbxDatabase(data, 'password');
  
  console.log('Entries:', db.getEntries());
</script>
```

### Node.js
```bash
npm install kdbx-wasm
```

```javascript
import { KdbxDatabase } from 'kdbx-wasm';
import fs from 'fs';

const data = fs.readFileSync('passwords.kdbx');
const db = new KdbxDatabase(new Uint8Array(data), 'password');
```

## 🔧 后续计划

- [ ] 添加更多测试
- [ ] 支持 KDBX 3.x
- [ ] 添加条目编辑功能
- [ ] 浏览器插件支持
- [ ] CLI 工具

## 📊 统计数据

| 指标 | 数值 |
|------|------|
| Rust 代码行数 | ~3000+ |
| WASM 模块大小 | 421 KB (优化后) |
| NPM 包大小 | 189 KB (压缩) |
| 支持格式 | KDBX 4 |
| 加密算法 | AES-256, ChaCha20 |
| KDF 算法 | Argon2d, Argon2id, AES-KDF |

---

**发布日期**: 2026-03-20  
**版本**: v0.1.1  
**状态**: ✅ 准备发布
