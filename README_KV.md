# ⚠️ 重要：配置 KV 存储

## 当前状态

✅ 代码已完成所有功能
❌ **KV 存储未配置**（导致进度和排行榜无法使用）

## 为什么需要 KV？

以下功能依赖 Cloudflare KV 存储：
- 🎯 用户进度追踪（24小时自动重置）
- 🏆 实时排行榜（10分钟刷新）
- ✅ 已完成关卡视觉标记
- 👥 访客统计

## 快速配置（3分钟）

### 方法：通过 Cloudflare Dashboard

> 适合你的 GitHub → Cloudflare 自动部署流程

#### 第1步：创建 KV Namespace

1. 打开 https://dash.cloudflare.com/
2. 左侧菜单：**Workers & Pages** → **KV**
3. 点击右上角 **Create a namespace**
4. 输入名称：`STATS_KV`
5. 点击 **Add**

✅ KV Namespace 创建完成！

#### 第2步：绑定到你的 Worker

1. 左侧菜单：**Workers & Pages** → 找到你的项目 `game`
2. 点击 **Settings** 标签
3. 左侧菜单点击 **Variables**
4. 滚动到 **KV Namespace Bindings** 部分
5. 点击 **Add binding** 按钮
6. 填写：
   - **Variable name**: 输入 `STATS_KV`（必须完全一致）
   - **KV namespace**: 下拉选择 `STATS_KV`
7. 点击 **Save**

✅ KV 绑定完成！

#### 第3步：触发重新部署

1. 去你的 GitHub 仓库
2. 编辑任意文件（比如在 README.md 末尾加个空行）
3. 提交并推送：
   ```bash
   git add .
   git commit -m "Trigger redeploy for KV binding"
   git push
   ```

或者在 Cloudflare Dashboard:
1. **Workers & Pages** → `game` → **Deployments**
2. 点击最新部署旁边的 **···** 菜单
3. 选择 **Retry deployment**

✅ 等待1-2分钟部署完成

#### 第4步：验证

1. 访问你的游戏网站
2. 完成任意一个关卡（比如 Level 1）
3. 刷新页面
4. 已完成的关卡应该显示：
   - 橙色发光边框
   - 右上角绿色 ✓ 标记
5. 点击"查看排行榜"按钮
6. 应该能看到你的排名

🎉 所有功能正常工作！

## 部署日志检查

重新部署后，查看日志应该显示：

```
✅ Successfully created binding for KV namespace STATS_KV
```

如果看到 `No bindings found`，说明KV未绑定成功。

## 可选：通过 wrangler.toml 配置

如果你想在代码中管理配置：

1. 在 Dashboard 创建 KV namespace 后，复制它的 ID
2. 编辑 `wrangler.toml`，取消注释并填入 ID：
   ```toml
   [[kv_namespaces]]
   binding = "STATS_KV"
   id = "你的KV-ID"
   ```
3. 提交到 GitHub

## 查看存储的数据

**Dashboard 查看**：
- Workers & Pages → KV → STATS_KV → Manage → View

**数据类型**：
- `progress:xxxxx` - 用户进度（24小时TTL）
- `leaderboard:data` - 排行榜（10分钟TTL）
- `global_stats` - 全局统计

## 详细文档

完整配置指南请查看：[CLOUDFLARE_DASHBOARD_SETUP.md](./CLOUDFLARE_DASHBOARD_SETUP.md)

## 故障排查

### 问题：进度不保存

**检查清单**：
- [ ] KV namespace 名称是 `STATS_KV`
- [ ] 绑定的 Variable name 是 `STATS_KV`（大小写敏感）
- [ ] 已触发重新部署
- [ ] 部署日志显示 "Successfully created binding"

### 问题：排行榜为空

**原因**：
- 需要至少完成1个关卡
- 10分钟缓存，可能需要等待

### 问题：部署失败

**检查**：
- wrangler.toml 中 KV 配置的 ID 是否正确
- binding 名称必须是 `STATS_KV`

## KV 用量（Free 计划）

- 读取：100,000 次/天
- 写入：1,000 次/天
- 存储：1 GB

对于 CTF 游戏完全够用！

---

**配置完成后，所有功能都将正常工作！🚀**
