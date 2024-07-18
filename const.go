package proxies

const (
	VersionSocks   = byte(0x05) // socks5协议版本号
	NegotiationVer = byte(0x01) // RFC-1929 sub-negotiation version 账号密码认证
)

const (
	Auth00 = byte(0x00) // 不需要认证(常用)
	Auth01 = byte(0x01) // GSSAPI认证
	Auth02 = byte(0x02) // 账号密码认证(常用)
	Auth03 = byte(0x03) // 0x03-0x7F IANA分配
	Auth80 = byte(0x80) // 0x80-0xFE 私有方法保留
	AuthFF = byte(0xFF) // 无支持的认证方法
)

const (
	Auth0000 = byte(0x00) // 不需要认证(常用)
	Auth0200 = byte(0x00) // 用户密码认证成功
	Auth0201 = byte(0x01) // 用户密码认证失败(大于0x00)
)

const (
	Cmd01 = byte(0x01) // CONNECT 连接上游服务器
	Cmd02 = byte(0x02) // BIND 绑定,客户端会接收来自代理服务器的链接,著名的FTP被动模式
	Cmd03 = byte(0x03) // UDP ASSOCIATE UDP中继
)

const (
	Rsv00 = byte(0x00) // 保留位 值是0x00
)

const (
	Rep00 = byte(0x00) // 0x00 代理服务器连接目标服务器成功
	Rep01 = byte(0x00) // 0x01 代理服务器故障
	Rep02 = byte(0x00) // 0x02 代理服务器规则集不允许连接
	Rep03 = byte(0x00) // 0x03 网络无法访问
	Rep04 = byte(0x00) // 0x04 目标服务器无法访问(主机名无效)
	Rep05 = byte(0x00) // 0x05 连接目标服务器被拒绝
	Rep06 = byte(0x00) // 0x06 TTL已过期
	Rep07 = byte(0x00) // 0x07 不支持的命令
	Rep08 = byte(0x00) // 0x08 不支持的目标服务器地址类型
	// 0x09 - 0xFF 未分配
)

const (
	AddressType01 = byte(0x01) // IPV4地址
	AddressType03 = byte(0x03) // 域名地址,域名地址的第1个字节为域名长度,剩下字节为域名名称字节数组
	AddressType04 = byte(0x04) // IPV6地址
)
