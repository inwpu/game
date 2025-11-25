# 🔐 网络安全闯关游戏

基于 Cloudflare Workers 的无状态 CTF 挑战平台，包含 Web 安全、密码学、协议分析等多个方向的 35 个精心设计的关卡。

## ✨ 特性

- **无需注册**: 基于 IP + 设备指纹的访客认证（24小时有效，自动重置）
- **动态 Flag**: 每个设备每天的 flag 都不同，防止答案共享
- **访客统计**: 实时显示访客数和访问数（使用 KV 存储）
- **打字机效果**: 首页动态展示网络安全知识，光标跟随文字
- **35 个关卡**: 从简单到专家级，全面覆盖安全领域
- **实时反馈**: 即时验证答案，提供详细提示
- **社区讨论**: 集成 Giscus 评论系统，方便玩家交流题目
- **黑客风格**: 终端绿色配色 + 炫光动画效果

## 🎮 关卡列表

### Web 安全类 (1-15)
| 关卡 | 名称 | 难度 | 描述 |
|------|------|------|------|
| 1 | HTTP Header Hunter | 简单 | HTTP 头部修改 |
| 2 | Method Matters | 简单 | HTTP 方法检测 |
| 3 | Referer Required | 简单 | Referer 头部伪造 |
| 4 | SQL Injection Detective | 中等 | SQL 注入识别 |
| 5 | JWT Inspector | 中等 | JWT 解析 |
| 6 | Cookie Monster | 中等 | Cookie 操纵 |
| 7 | SSRF Spotter | 困难 | SSRF 漏洞检测 |
| 8 | XSS Hunter | 中等 | XSS 攻击识别 |
| 9 | CORS Bypass | 困难 | CORS 机制理解 |
| 10 | Path Traversal | 中等 | 目录遍历攻击 |
| 11 | Command Injection | 困难 | 命令注入识别 |
| 12 | XXE Explorer | 困难 | XML 外部实体注入 |
| 13 | CSRF Defender | 中等 | CSRF 防护机制 |
| 14 | Response Splitting | 困难 | HTTP 响应拆分 |
| 15 | Upload Bypass | 困难 | 文件上传绕过 |

### 密码学类 (16-25)
| 关卡 | 名称 | 难度 | 描述 |
|------|------|------|------|
| 16 | Base64 Decoder | 简单 | Base64 解码 |
| 17 | XOR Cipher | 中等 | XOR 加密破解 |
| 18 | Caesar Shift | 简单 | 凯撒密码 (ROT13) |
| 19 | Hash Collision | 中等 | MD5 碰撞理解 |
| 20 | AES Master | 中等 | AES 密钥长度 |
| 21 | RSA Keys | 中等 | RSA 公私钥理解 |
| 22 | Hex Decoder | 简单 | 十六进制转 ASCII |
| 23 | Rainbow Table | 困难 | 彩虹表防御 |
| 24 | Crypto Types | 简单 | 对称/非对称加密 |
| 25 | Key Exchange | 困难 | Diffie-Hellman 算法 |

### 协议分析类 (26-30)
| 关卡 | 名称 | 难度 | 描述 |
|------|------|------|------|
| 26 | Status Code 418 | 简单 | HTTP 状态码 |
| 27 | DNS Records | 中等 | DNS 记录类型 |
| 28 | TCP Handshake | 中等 | TCP 三次握手 |
| 29 | TLS Version | 中等 | TLS 版本选择 |
| 30 | WebSocket Upgrade | 困难 | WebSocket 协议 |

### 进阶挑战 (31-35)
| 关卡 | 名称 | 难度 | 描述 |
|------|------|------|------|
| 31 | Regex Bypass | 困难 | 正则表达式绕过 |
| 32 | JWT Algorithm None | 困难 | JWT None 算法漏洞 |
| 33 | Timing Attack | 困难 | 时序攻击防御 |
| 34 | HSTS Header | 中等 | HSTS 头部理解 |
| 35 | Final Challenge | 专家 | 最终综合挑战 |

## 🚀 快速开始

### 1. 安装依赖

\`\`\`bash
npm install
\`\`\`

### 2. 本地开发

\`\`\`bash
npm run dev
\`\`\`

访问 http://localhost:8787

### 3. 配置 KV 存储（用于访客统计）

\`\`\`bash
# 创建生产环境 KV 命名空间
wrangler kv:namespace create "STATS_KV"

# 创建预览环境 KV 命名空间
wrangler kv:namespace create "STATS_KV" --preview

# 将返回的 id 填入 wrangler.toml 的 kv_namespaces 配置中
\`\`\`

### 4. 部署到 Cloudflare Workers

\`\`\`bash
# 登录 Cloudflare
wrangler login

# 查看账户信息
wrangler whoami

# 修改 wrangler.toml 中的 account_id 和 KV namespace id

# 部署
npm run deploy
\`\`\`

## 🔧 技术架构

### 后端 (Cloudflare Workers)

- **设备指纹生成**: 基于 User-Agent、Accept-Language 等多个维度
- **访客认证**: IP + 设备指纹 + 时间戳（24小时周期）
- **动态 Flag**: \`hash(levelId + fingerprint + dayTimestamp)\`
- **访客统计**: 使用 KV 存储统计访客数和访问数
- **无状态验证**: 所有逻辑在单次请求中完成

### 前端

- **原生 JavaScript**: 无框架依赖
- **打字机效果**: 动态展示网络安全知识，光标跟随文字
- **响应式设计**: 支持移动端和桌面端
- **实时交互**: Fetch API + 模态框
- **悬浮信息窗**: 显示 IP、指纹、访客数和访问数，10秒后自动隐藏
- **Giscus 评论**: 基于 GitHub Discussions 的社区讨论功能

## 📁 项目结构

\`\`\`
game/
├── src/
│   └── index.js          # Workers 主文件（包含后端逻辑和前端 HTML）
├── wrangler.toml         # Cloudflare Workers 配置
├── package.json          # 项目配置
└── README.md            # 说明文档
\`\`\`

## 🎯 关卡设计思路

### Web 安全类
- **HTTP Header Hunter**: 学习 HTTP 头部修改
- **SQL Injection Detective**: 识别危险的 SQL 注入模式
- **JWT Inspector**: 理解 JWT 结构和安全性
- **SSRF Spotter**: 识别服务器端请求伪造
- **Cookie Monster**: Cookie 伪造和权限绕过

### 密码学类
- **Base64 Decoder**: 基础编码
- **XOR Cipher**: 对称加密原理
- **Caesar Shift**: 古典密码学
- **AES Master**: 现代加密标准

### HTTP 协议类
- **Method Matters**: HTTP 方法的区别和用途

## 🔐 安全设计

1. **动态 Flag**: 基于设备指纹和日期生成，防止答案传播
2. **24小时周期**: 每天重置，鼓励重复挑战
3. **无状态**: 不存储用户数据，保护隐私
4. **访客认证**: 仅用于区分不同设备，不涉及敏感信息

## 🛠️ API 端点

\`\`\`
GET  /                    # 游戏主页（包含打字机效果）
GET  /api/visitor         # 获取访客信息（IP、指纹、访客数、访问数）
GET  /api/stats           # 获取全局统计信息
GET  /api/levels          # 获取关卡列表
GET  /api/level/:id       # 获取关卡详情
POST /api/submit          # 提交答案
\`\`\`

## 📝 答案提交格式

\`\`\`json
{
  "levelId": 1,
  "answer": "用户答案"
}
\`\`\`

## 🎨 界面特色

- **黑客风格**: 终端绿色 + 深色背景
- **打字机动画**: 首页循环展示 10 条安全知识，光标闪烁跟随
- **炫光效果**: 边框动画和悬停效果
- **响应式卡片**: 网格布局，自适应屏幕
- **悬浮信息窗**: 右下角显示 IP、指纹、访客数、访问数
- **评论讨论区**: 页面底部集成 Giscus，支持 GitHub 登录讨论

## 📊 性能优化

- **单文件部署**: 所有代码打包在一个 Worker 中
- **无外部依赖**: 纯原生实现，启动速度快
- **全球分发**: 利用 Cloudflare 边缘网络
- **即时响应**: 无数据库查询，毫秒级返回

## 🔄 扩展建议

1. **更多关卡**: 继续添加新的安全主题（已有 35 个关卡）
2. **排行榜**: 使用 KV 存储完成时间和排名
3. **提示系统**: 多级提示，消耗虚拟货币
4. **成就系统**: 完成特定组合获得徽章
5. **社交分享**: 生成战绩图片分享
6. **难度评级**: 根据通过率动态调整关卡难度
7. **学习路径**: 推荐关卡学习顺序

## 📄 许可证

MIT License

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

🎮 **开始挑战，成为安全专家！**
