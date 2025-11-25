#!/bin/bash

# KV Namespace 配置脚本
# 此脚本会自动创建KV namespace并更新wrangler.toml

echo "========================================="
echo "创建 Cloudflare KV Namespace"
echo "========================================="

# 创建生产环境 KV namespace
echo ""
echo "步骤 1: 创建生产环境 KV namespace..."
PROD_OUTPUT=$(wrangler kv:namespace create "STATS_KV" 2>&1)
echo "$PROD_OUTPUT"

# 提取 ID
PROD_ID=$(echo "$PROD_OUTPUT" | grep -oP 'id = "\K[^"]+' || echo "")

if [ -z "$PROD_ID" ]; then
  echo "❌ 错误: 无法创建生产环境 KV namespace"
  exit 1
fi

echo "✅ 生产环境 ID: $PROD_ID"

# 创建预览环境 KV namespace
echo ""
echo "步骤 2: 创建预览环境 KV namespace..."
PREVIEW_OUTPUT=$(wrangler kv:namespace create "STATS_KV" --preview 2>&1)
echo "$PREVIEW_OUTPUT"

# 提取 preview ID
PREVIEW_ID=$(echo "$PREVIEW_OUTPUT" | grep -oP 'preview_id = "\K[^"]+' || echo "")

if [ -z "$PREVIEW_ID" ]; then
  echo "❌ 错误: 无法创建预览环境 KV namespace"
  exit 1
fi

echo "✅ 预览环境 ID: $PREVIEW_ID"

# 更新 wrangler.toml
echo ""
echo "步骤 3: 更新 wrangler.toml..."

# 备份原文件
cp wrangler.toml wrangler.toml.backup

# 替换配置
sed -i.tmp "s/# \[\[kv_namespaces\]\]/[[kv_namespaces]]/g" wrangler.toml
sed -i.tmp "s/# binding = \"STATS_KV\"/binding = \"STATS_KV\"/g" wrangler.toml
sed -i.tmp "s/# id = \"your-kv-namespace-id\"/id = \"$PROD_ID\"/g" wrangler.toml
sed -i.tmp "s/# preview_id = \"your-preview-kv-namespace-id\"/preview_id = \"$PREVIEW_ID\"/g" wrangler.toml

# 清理临时文件
rm wrangler.toml.tmp 2>/dev/null

echo "✅ wrangler.toml 已更新"

# 显示最终配置
echo ""
echo "========================================="
echo "配置完成！"
echo "========================================="
echo ""
echo "已添加以下配置到 wrangler.toml:"
echo ""
echo "[[kv_namespaces]]"
echo "binding = \"STATS_KV\""
echo "id = \"$PROD_ID\""
echo "preview_id = \"$PREVIEW_ID\""
echo ""
echo "现在可以运行以下命令部署:"
echo "  npm run deploy"
echo ""
echo "备份文件已保存为: wrangler.toml.backup"
echo "========================================="
