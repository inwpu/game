# Cloudflare Dashboard KV 配置指南

## 适用场景

通过 GitHub 自动部署到 Cloudflare Workers & Pages

## 配置步骤

### 第一步：创建 KV Namespace

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)

2. 进入 **Workers & Pages** → **KV**

3. 点击 **Create a namespace**

4. 输入名称：`STATS_KV`

5. 点击 **Add**

6. **记下创建的 Namespace ID**（类似 `abc123def456...`）

### 第二步：绑定 KV 到你的 Worker

#### 方法 1：通过 Dashboard 绑定（推荐）

1. 进入 **Workers & Pages** → 找到你的项目 `game`

2. 点击 **Settings** → **Variables**

3. 在 **KV Namespace Bindings** 部分，点击 **Add binding**

4. 填写：
   - **Variable name**: `STATS_KV`
   - **KV namespace**: 选择刚才创建的 `STATS_KV`

5. 点击 **Save**

6. **触发重新部署**：
   - 去 GitHub 仓库
   - 提交一个小改动（如在 README 末尾加个空行）
   - Cloudflare 会自动重新部署

#### 方法 2：通过 wrangler.toml 配置

1. 复制你创建的 KV Namespace ID

2. 编辑 `wrangler.toml`，找到这几行：

```toml
# [[kv_namespaces]]
# binding = "STATS_KV"
# id = "your-kv-namespace-id"
# preview_id = "your-preview-kv-namespace-id"
```

3. 取消注释并填入实际的 ID：

```toml
[[kv_namespaces]]
binding = "STATS_KV"
id = "你的KV-Namespace-ID"  # 替换为实际ID
```

**注意**：preview_id 对于 Pages 部署是可选的，可以不填。

4. 提交到 GitHub：

```bash
git add wrangler.toml
git commit -m "Configure KV namespace"
git push
```

5. Cloudflare 会自动重新部署

### 第三步：验证配置

1. 等待部署完成（约1-2分钟）

2. 查看部署日志：
   - Cloudflare Dashboard → Workers & Pages → game → Deployments
   - 点击最新的部署
   - 查看日志，应该看到类似：
     ```
     ✅ Successfully created binding for KV namespace STATS_KV
     ```

3. 访问你的网站测试：
   - 完成一个关卡
   - 刷新页面
   - 已完成的关卡应该有橙色边框
   - 点击"查看排行榜"应该能看到你的排名

## 两种方法对比

| 方法 | 优点 | 缺点 |
|------|------|------|
| **Dashboard 绑定** | 不需要修改代码，立即生效 | 需要手动配置 |
| **wrangler.toml** | 代码版本控制，便于管理 | 需要提交代码触发部署 |

**推荐**：先用 Dashboard 绑定快速测试，确认可用后再更新 wrangler.toml。

## 查看 KV 中的数据

### 通过 Dashboard

1. Workers & Pages → KV → STATS_KV

2. 可以看到所有存储的键值：
   - `progress:xxxxx` - 用户进度
   - `leaderboard:data` - 排行榜数据
   - `global_stats` - 访客统计

### 通过 Wrangler CLI

```bash
# 列出所有键
wrangler kv:key list --namespace-id=你的KV-ID

# 查看特定键的值
wrangler kv:key get "leaderboard:data" --namespace-id=你的KV-ID
```

## 常见问题

### Q: 部署日志显示 "No bindings found"

**A**: KV 未绑定，请按照上述步骤绑定 KV namespace。

### Q: 完成关卡后进度不保存

**A**: 检查：
1. KV 是否已创建
2. 绑定名称是否为 `STATS_KV`（必须完全一致）
3. 是否重新部署

### Q: 排行榜显示"暂无数据"

**A**:
1. 确保至少完成了1个关卡
2. 等待10秒后刷新排行榜
3. 检查浏览器控制台是否有错误

### Q: 我想清空所有进度数据

**A**:
1. Dashboard → Workers & Pages → KV → STATS_KV
2. 点击 "Manage" → "View"
3. 逐个删除键，或删除整个 namespace 重新创建

## 自动部署流程

```
GitHub Push
    ↓
Cloudflare 检测到变更
    ↓
自动构建
    ↓
应用 wrangler.toml 配置
    ↓
绑定 KV (如果配置了)
    ↓
部署完成
```

## 下一步

配置完成后，你的游戏将具备：
- ✅ 用户进度追踪（24小时自动重置）
- ✅ 实时排行榜（10分钟自动刷新）
- ✅ 已完成关卡视觉标记
- ✅ Flag MD5 加密显示

所有功能都会正常工作！
