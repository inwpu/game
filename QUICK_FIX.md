# 快速修复指南

## 问题总结

1. ✅ **wrangler.toml配置警告** - 已修复
2. ✅ **flag MD5加密** - 已添加
3. ⚠️ **进度不更新** - 需要配置KV
4. ⚠️ **排行榜无数据** - 需要配置KV

## 修复内容

### 1. 修复了wrangler.toml警告

移除了不支持的配置项 `traces` 和 `persist`。

### 2. 添加了flag MD5加密

现在每次正确提交都会返回:
- `flag`: 用户可读的flag（如 `flag{SecurityBot/1.0}`）
- `flagHash`: MD5加密的唯一标识

示例响应:
```json
{
  "passed": true,
  "flag": "flag{SecurityBot/1.0}",
  "flagHash": "a1b2c3d4e5f6...",
  "message": "恭喜！..."
}
```

前端会显示:
```
flag{SecurityBot/1.0}
MD5: a1b2c3d4e5f6...
```

### 3. 配置KV存储（必需）

**进度追踪和排行榜功能需要KV存储！**

#### 方法1: 自动配置（推荐）

```bash
cd /Users/return0/Desktop/5aes/game
./SETUP_KV.sh
```

这个脚本会:
1. 创建生产环境 KV namespace
2. 创建预览环境 KV namespace
3. 自动更新 wrangler.toml

#### 方法2: 手动配置

```bash
# 1. 创建KV namespace
wrangler kv:namespace create "STATS_KV"
wrangler kv:namespace create "STATS_KV" --preview

# 2. 复制输出的ID
# 示例输出:
# id = "abc123..."
# preview_id = "def456..."

# 3. 编辑 wrangler.toml，取消注释并填入ID:
[[kv_namespaces]]
binding = "STATS_KV"
id = "你的-kv-namespace-id"
preview_id = "你的-preview-namespace-id"
```

### 4. 重新部署

```bash
npm run deploy
```

## 验证修复

部署后访问游戏页面:

1. ✅ **flag MD5显示**
   - 完成任意关卡
   - 查看返回的flag下方应该显示MD5 hash

2. ✅ **进度保存**
   - 完成一个关卡
   - 刷新页面
   - 已完成的关卡应该有橙色边框和✓标记

3. ✅ **排行榜**
   - 点击"查看排行榜"按钮
   - 应该能看到你的排名和完成数

## 如果仍有问题

### 问题: "No bindings found"

**原因**: 没有配置KV namespace

**解决**: 运行 `./SETUP_KV.sh` 或手动配置KV

### 问题: 进度不保存

**检查**:
1. KV是否配置正确
2. 部署日志中是否显示 "Successfully created binding for KV namespace"
3. 浏览器控制台是否有错误

**调试**:
```bash
# 查看KV列表
wrangler kv:namespace list

# 查看KV中的数据
wrangler kv:key list --binding=STATS_KV
```

### 问题: 排行榜为空

**原因**:
1. 还没有人完成关卡（至少需要完成1个）
2. KV未配置

**解决**: 完成任意一个关卡后等待10秒，刷新排行榜

## 部署日志示例（正确）

```
✅ Successfully created binding for KV namespace STATS_KV
Total Upload: 89.09 KiB / gzip: 18.95 KiB
Deployed game triggers (0.51 sec)
  https://game.snnuisdc.workers.dev
```

如果看到 "No bindings found"，说明KV未配置！

## 更新日志

- 2025-11-25: 修复wrangler.toml警告
- 2025-11-25: 添加flag MD5加密
- 2025-11-25: 创建KV自动配置脚本
