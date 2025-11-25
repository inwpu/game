# 调试访问失败问题

## 1. 查看实时日志

在终端运行：

```bash
cd /Users/return0/Desktop/5aes/game
wrangler tail
```

然后访问你的网站，查看实时错误信息。

## 2. 在浏览器查看错误

1. 打开浏览器开发者工具（F12）
2. 切换到 **Console** 标签
3. 访问 https://game.snnuisdc.workers.dev 或 https://game.hxorz.cn
4. 查看是否有红色错误信息

## 3. 检查 Worker 日志

1. 登录 Cloudflare Dashboard
2. Workers & Pages → game → Logs
3. 查看最近的错误日志

## 常见错误原因

### 错误1: 500 Internal Server Error

**可能原因**：代码中有语法错误或运行时错误

**解决**：查看 `wrangler tail` 的输出

### 错误2: 白屏或加载失败

**可能原因**：
- DNS 还在传播中（等待5-10分钟）
- 自定义域名未正确配置

**检查**：
- 访问 Workers 域名：https://game.snnuisdc.workers.dev
- 如果 Workers 域名可以访问，说明是自定义域名问题

### 错误3: 页面能打开但功能不工作

**可能原因**：JavaScript 错误

**检查浏览器控制台**：
- 是否有 CORS 错误
- 是否有 API 调用失败

### 错误4: KV 相关错误

**症状**：页面能打开，但提示 KV 相关错误

**检查**：
```bash
# 验证 KV 绑定
wrangler kv:namespace list

# 应该看到:
# ┌──────────────────────────────────┬──────────┐
# │ id                               │ title    │
# ├──────────────────────────────────┼──────────┤
# │ 8ae1c2569cdd4a6ea50ad81873a26f74 │ STATS_KV │
# └──────────────────────────────────┴──────────┘
```

## 4. 测试 API 端点

使用 curl 测试：

```bash
# 测试主页
curl https://game.snnuisdc.workers.dev/

# 测试访客信息
curl https://game.snnuisdc.workers.dev/api/visitor

# 测试关卡列表
curl https://game.snnuisdc.workers.dev/api/levels

# 测试进度 API
curl https://game.snnuisdc.workers.dev/api/progress

# 测试排行榜
curl https://game.snnuisdc.workers.dev/api/leaderboard
```

如果返回 HTML 或 JSON，说明 Worker 正常工作。

## 5. 快速测试脚本

保存为 `test.sh` 并运行：

```bash
#!/bin/bash

URL="https://game.snnuisdc.workers.dev"

echo "Testing homepage..."
curl -s "$URL" | head -n 5

echo ""
echo "Testing API endpoints..."
curl -s "$URL/api/visitor" | jq .

echo ""
echo "Testing levels..."
curl -s "$URL/api/levels" | jq 'length'

echo ""
echo "Testing progress..."
curl -s "$URL/api/progress" | jq .

echo ""
echo "Testing leaderboard..."
curl -s "$URL/api/leaderboard" | jq .
```

## 请提供以下信息

1. **具体错误信息**：
   - 浏览器显示什么？（截图或文字）
   - 控制台有什么错误？

2. **访问的 URL**：
   - game.snnuisdc.workers.dev 能访问吗？
   - game.hxorz.cn 能访问吗？

3. **`wrangler tail` 输出**：
   - 访问时显示什么错误？

4. **浏览器控制台**：
   - 有红色错误吗？复制给我

有了这些信息，我可以精确定位问题！
