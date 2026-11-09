#!/usr/bin/env bash
# install-xray-reality.sh
# Debian 12/13 · 纯净 Xray-core
# 入站: vless + reality (tcp)，支持 UDP 转发（UDP over TCP）
# 用法: sudo bash install-xray-reality.sh

set -euo pipefail

VLESS_PORT=443
XRAY_DIR="/usr/local/etc/xray"
XRAY_BIN="/usr/local/bin/xray"
SERVICE_FILE="/etc/systemd/system/xray.service"
CONFIG="$XRAY_DIR/config.json"

# reality 参数（按需修改伪装域名）
SNI="www.microsoft.com"
FINGERPRINT="chrome"
SPIDERX="/"

[[ $EUID -eq 0 ]] || { echo "[!] 请用 root 运行"; exit 1; }

# ---------- 架构 ----------
case "$(uname -m)" in
  x86_64|amd64)  ARCH="64" ;;
  aarch64|arm64) ARCH="arm64-v8a" ;;
  armv7l)        ARCH="arm32-v7a" ;;
  *) echo "[!] 不支持的架构: $(uname -m)"; exit 1 ;;
esac
echo "[*] 架构: $(uname -m) -> $ARCH"

# ---------- 依赖 ----------
echo "[*] 安装依赖..."
apt-get update -y
apt-get install -y curl unzip ca-certificates openssl

# ---------- 下载 Xray ----------
echo "[*] 获取最新版本..."
TAG=$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest \
      | grep -oP '"tag_name":\s*"\K[^"]+')
[[ -n "$TAG" ]] || { echo "[!] 获取版本失败"; exit 1; }
echo "[*] 版本: $TAG"

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
URL="https://github.com/XTLS/Xray-core/releases/download/${TAG}/Xray-linux-${ARCH}.zip"
echo "[*] 下载: $URL"
curl -fL --retry 3 -o "$TMP/xray.zip" "$URL"
unzip -q "$TMP/xray.zip" -d "$TMP"
install -m 755 "$TMP/xray" "$XRAY_BIN"
echo "[*] 已安装: $("$XRAY_BIN" version | head -n1)"

# ---------- 生成 reality 密钥 ----------
echo "[*] 生成 reality 密钥对..."
KEYS=$("$XRAY_BIN" x25519)
PRIVATE_KEY=$(echo "$KEYS" | grep -i 'Private' | awk '{print $NF}')
PUBLIC_KEY=$(echo "$KEYS"  | grep -i 'Public'  | awk '{print $NF}')
SHORT_ID=$(openssl rand -hex 8)
UUID=$("$XRAY_BIN" uuid)

echo "    privateKey: $PRIVATE_KEY"
echo "    publicKey : $PUBLIC_KEY"
echo "    shortId   : $SHORT_ID"
echo "    uuid      : $UUID"

# ---------- 生成 config.json ----------
mkdir -p "$XRAY_DIR"
cat > "$CONFIG" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vless-reality-in",
      "listen": "0.0.0.0",
      "port": ${VLESS_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${UUID}", "flow": "xtls-rprx-vision" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "target": "${SNI}:443",
          "xver": 0,
          "serverNames": [ "${SNI}" ],
          "privateKey": "${PRIVATE_KEY}",
          "shortIds": [ "${SHORT_ID}" ],
          "fingerprint": "${FINGERPRINT}",
          "spiderX": "${SPIDERX}"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [ "http", "tls" ],
        "routeOnly": true
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct",
      "settings": { "domainStrategy": "UseIP" }
    }
  ]
}
EOF
echo "[*] 已生成配置: $CONFIG"

# ---------- systemd ----------
cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=Xray Service
Documentation=https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now xray
systemctl --no-pager --full status xray | head -n 12 || true

# ---------- 输出客户端连接信息 ----------
SERVER_IP=$(curl -fsSL https://api.ipify.org || echo "YOUR_SERVER_IP")
VLESS_LINK="vless://${UUID}@${SERVER_IP}:${VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=${FINGERPRINT}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&spx=${SPIDERX}&type=tcp#reality-${SERVER_IP}"

cat <<RESULT

==================== 安装完成 ====================
配置   : $CONFIG
入站   : vless + reality  tcp  0.0.0.0:${VLESS_PORT}
UDP    : 支持（UDP over TCP，随 VLESS 自动转发）

--- 客户端信息 ---
服务器   : ${SERVER_IP}
端口     : ${VLESS_PORT}
UUID     : ${UUID}
SNI      : ${SNI}
Flow     : xtls-rprx-vision
Fingerprint : ${FINGERPRINT}
PublicKey   : ${PUBLIC_KEY}
ShortId     : ${SHORT_ID}
SpiderX     : ${SPIDERX}

--- vless 链接 ---
${VLESS_LINK}

查看日志: journalctl -u xray -f
重启服务: systemctl restart xray
==================================================
RESULT