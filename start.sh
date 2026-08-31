#!/bin/bash
echo "========================================"
echo "  TG 采集工具 Pro 版"
echo "========================================"
echo ""

# 安装依赖
echo "正在检查依赖..."
pip3 install -r requirements.txt -q 2>/dev/null

# 创建必要目录
mkdir -p data output static

# 启动面板
echo ""
echo "启动面板服务..."
echo "访问地址: http://0.0.0.0:8090"
echo ""
python3 app.py
