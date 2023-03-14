# xray-install

Xray installation and configuraion script for **`Ubuntu`** and **`Debian`** servers.

**>> [چگونه هوشمندانه سوال بپرسیم و مشکلاتمان را مطرح کنیم](https://github.com/sergeantreacher/smart-question/blob/master/readme.md) <<**

## Features

- Automaticly install and configure [Xray-core](https://github.com/XTLS/Xray-core)
- Check exit code of every command that executed (No more nonsense errors).
- User Management with unique UUID/Password for each user
- VLess, VMess and Trojan Support
- XTLS for VLess and Trojan Support 
- VPS Basic settings for better experience
- Enable TCP BBR with [teddysun script](https://github.com/teddysun/across/blob/master/bbr.sh)
- Saving backups and bundle them in `.tar.gz` files for easy download.


## Install

#### Install Dependencies

```bash
apt update && apt install curl
```

#### Run Script

```bash
bash -c "$(curl -L https://github.com/thehxdev/xray-install/raw/main/xray.sh)"
```


## User Management

**User Management added to main script!**
- **I changed user management system a little. If it not works in your server, Uninstall Xray and install it again.**


## Supported protocols

- It's better to use **TLS** supported protocols.
- Configs that has **Nginx**  option, will setup a fake website.
- Protocols that support **Websocket (WS)** can be used with **CDN**.
- As of Xray-Core v1.8.0 changes, the `XTLS-direct` method is **deprecated** and
it's better to change your configuration if you're using it.

1. [VLESS + WS + TLS](https://github.com/thehxdev/xray-examples/tree/main/VLESS-Websocket-TLS-s)
1. [VLESS + TCP + TLS](https://github.com/thehxdev/xray-examples/tree/main/VLESS-TCP-TLS-Minimal-s)
1. [VMESS + WS](https://github.com/thehxdev/xray-examples/tree/main/VMess-Websocket-s)
1. [VMESS + WS + TLS](https://github.com/thehxdev/xray-examples/tree/main/VMess-Websocket-TLS-s)
1. [VMESS + WS + Nginx](https://github.com/thehxdev/xray-examples/tree/main/VMess-Websocket-Nginx-s)
1. [VMESS + WS + Nginx + TLS](https://github.com/thehxdev/xray-examples/tree/main/VMess-Websocket-Nginx-TLS-s)
1. [VMESS + TCP](https://github.com/thehxdev/xray-examples/tree/main/VMess-TCP-s)
1. [VMESS + TCP + TLS](https://github.com/thehxdev/xray-examples/tree/main/VMess-TCP-TLS-s)
1. [Trojan + TCP + TLS](https://github.com/thehxdev/xray-examples/tree/main/Trojan-TCP-TLS-s)
1. [Trojan + WS + TLS](https://github.com/thehxdev/xray-examples/tree/main/Trojan-Websocket-TLS-s)


## Deprecated and Removed configs

1. [Trojan + TCP + XTLS (Deprecated - Removed)](https://github.com/thehxdev/xray-examples/tree/main/Trojan-TCP-XTLS-s)
1. [Ultimate Config (All Configs + VLESS XTLS-direct) (Deprecated - Removed)](https://github.com/thehxdev/xray-examples/blob/main/VLESS-TCP-XTLS-WHATEVER)

