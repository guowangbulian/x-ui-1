# x-ui

支持多协议多用户的 xray 面板。

由于某人的人情世故，故此xui面板暂不开源，介意者勿用！！！

# 功能介绍

- 系统状态监控
- 支持多协议、单端口多用户，网页可视化操作
- 支持的协议：vmess、vless、trojan、shadowsocks、dokodemo-door、socks、http
- 支持配置更多传输配置
- 流量统计，限制流量，限制到期时间
- 可自定义 xray 配置模板
- 支持 https 访问面板（自备域名 + ssl 证书）
- 支持一键SSL证书申请且自动续签
- 更多高级配置项，详见面板

# 安装&升级

```shell
bash <(curl -Ls https://raw.githubusercontent.com/guowangbulian/x-ui-1/main/install.sh)
```

```shell
wget -N --no-check-certificate https://gitlab.com/misakablog/x-ui/-/raw/main/install.sh && bash install.sh
```

## Telegram 机器人使用

本X-UI面板支持通过Telegram机器人实现每日流量通知，面板登录提醒等功能。使用此功能需要自行申请

- Tg机器人Token
- Tg机器人ChatId
- Tg机器人周期运行时间，采用crontab语法  

参考语法：
- 30 * * * * * //每一分的第30s进行通知
- @hourly      //每小时通知
- @daily       //每天通知（凌晨零点整）
- @every 8h    //每8小时通知  

TG通知内容：
- 节点流量使用
- 面板登录提醒
- 节点到期提醒
- 流量预警提醒 

## 建议系统

- CentOS 7+
- Ubuntu 16+
- Debian 8+

## 赞助我们

爱发电：https://afdian.net/a/misaka-blog

## 频道及交流群

[Telegram 频道](https://t.me/misakablogchannel)

[Telegram 群组](https://t.me/+CLhpemKhaC8wZGIx)

## License
GNU Affero General Public License v3.0
