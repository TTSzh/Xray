#!/bin/bash

# 检查root权限并更新系统
root() {
    if [[ ${EUID} -ne 0 ]]; then
        echo "Error: This script must be run as root!" 1>&2
        exit 1
    fi
    echo "正在更新系统和安装依赖"
    if [ -f "/usr/bin/apt-get" ]; then
        apt-get update -y && apt-get upgrade -y
        apt-get install -y gawk curl openssl
    else
        yum update -y && yum upgrade -y
        yum install -y epel-release gawk curl openssl
    fi
}

# 配置和启动 Xray
xray() {
    # 安装 Xray 内核
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

    # 固定端口
    PORT1=44448    # Shadowsocks 2022 固定端口
    PORT2=2096     # VLESS+REALITY+XHTTP 固定端口

    # 生成随机参数
    path=$(openssl rand -hex 6)
    uuid=$(cat /proc/sys/kernel/random/uuid)
    psk=$(openssl rand -base64 16 | tr -d '\n')
    psk_urlsafe=$(echo -n "$psk" | tr '+/' '-_')
    X25519Key=$(/usr/local/bin/xray x25519)
    PrivateKey=$(echo "${X25519Key}" | head -1 | awk '{print $3}')
    PublicKey=$(echo "${X25519Key}" | tail -n 1 | awk '{print $3}')

    # 写入 config.json
    cat >/usr/local/etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": ${PORT1},
      "protocol": "shadowsocks",
      "settings": {
        "method": "2022-blake3-aes-128-gcm",
        "password": "${psk}",
        "network": "tcp,udp"
      }
    },
    {
      "port": ${PORT2},
      "protocol": "vless",
      "settings": {
        "clients":[{ "id":"${uuid}", "flow":"" }],
        "decryption":"none","fallbacks":[]
      },
      "streamSettings":{
        "network":"xhttp","security":"reality",
        "realitySettings":{
          "show":false,"dest":"www.tesla.com:443","xver":0,
          "serverNames":["www.tesla.com"],
          "privateKey":"${PrivateKey}",
          "shortIds":["123abc"],
          "fingerprint":"chrome"
        },
        "xhttpSettings":{
          "path":"${path}","host":"","headers":{},
          "scMaxBufferedPosts":30,"scMaxEachPostBytes":"1000000",
          "noSSEHeader":false,"xPaddingBytes":"100-1000","mode":"auto"
        }
      },
      "sniffing":{ "enabled":true,"destOverride":["http","tls","quic"] }
    }
  ],
  "outbounds":[{ "protocol":"freedom","tag":"direct" }]
}
EOF

    # 启用并重启服务
    systemctl enable xray.service
    systemctl restart xray.service

    # 生成客户端 config.txt
    HOST_IP=$(curl -s4 http://www.cloudflare.com/cdn-cgi/trace | awk -F= '/ip/ {print $2}')
    [[ -z "$HOST_IP" ]] && HOST_IP=$(curl -s6 http://www.cloudflare.com/cdn-cgi/trace | awk -F= '/ip/ {print $2}')
    IP_COUNTRY=$(curl -s http://ipinfo.io/${HOST_IP}/country)

    cat >/usr/local/etc/xray/config.txt <<EOF
ss://2022-blake3-aes-128-gcm:${psk_urlsafe}@${HOST_IP}:${PORT1}#${IP_COUNTRY}

vless://${uuid}@${HOST_IP}:${PORT2}?encryption=none&security=reality&sni=www.tesla.com&fp=chrome&pbk=${PublicKey}&sid=123abc&type=xhttp&path=%2F${path}&mode=auto#${IP_COUNTRY}
EOF

    echo "Xray 安装完成，配置写入 /usr/local/etc/xray/config.txt"
}

main() {
    root
    xray
}

main
