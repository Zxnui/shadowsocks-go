# 简介  
如果你只是想使用shadowsocks，请访问[shadowsocks](https://github.com/shadowsocks/shadowsocks-go).

## 项目目录
- cmd  
1. server.go 
//服务入口
2. local.go 
//客户端入口
3. httpget.go
- deb  
- sample-config  
- script  
- shadowsocks  
1. config.go 
//对配置文件的解析
2. conn.go 
//tcp代理实现
3. encrypt.go 
//提供统一加密解码
4. leakybuf.go 
//缓冲
5. log.go 
//日志
6. mergesort.go 
7. pipe.go
8. proxy.go
9. udp.go
10. udprelay.go
11. util.go