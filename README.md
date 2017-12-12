# 简介  
如果你只是想使用shadowsocks，请访问[shadowsocks](https://github.com/shadowsocks/shadowsocks-go).

## 项目目录
- cmd  
1. server.go 
服务入口，接受local发送过来的数据，解密后发给用户想要访问的目标服务器。统御调度各组件的具体过程，都在其中  
2. local.go 
客户端入口
3. httpget.go
- deb  
- sample-config  
- script  
- shadowsocks  
1. config.go 
对配置文件的解析  

2. conn.go 
tcp代理实现，数据底层处理详情  

3. encrypt.go 
提供统一加密解码  

4. leakybuf.go 
缓冲  

5. log.go 
日志  

6. mergesort.go 
7. pipe.go  
conn.go上层，处理数据的加密和转发  

8. proxy.go
9. udp.go
10. udprelay.go
11. util.go
一些公共的方法，打印版本信息