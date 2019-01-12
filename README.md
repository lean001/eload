## eload
----
类似ab的压测工具，使用方法
```
cd eload/; make
./eload -l http://www.example.com/
```

### Usage
```
 eload [OPTIONS] http://hostname[:port]/path
    -h                show Usage
    -l <url>          example: -l 'http://www.qq.com/'
    -p <file>         the POST payload
    -T <content-type> Content-type header to use for POST data
                      eg. 'application/x-www-form-urlencoded'
    -c <connections>  total connections
    -t <thread>       the number of threads
    -r <rate>         N con/sec, NOTE: rate >= threads

     ./eload -t 1 -c 100 -r 10 -l http://www.qq.com/
```

### 输出说明
```
2019-01-12 22:45:59# succ: 14 active: 100  finish: 1948  free: 1855  timeout: 97  error: 0
# succ    当前请求成功的连接数
# active  当前正在进行的连接数
# finish  已成功完成的连接数
# free    剩余未开始的连接数
# timeout 已超时关闭的连接数
# error   错误关闭的的连接数


Overview:
tcp status closed       3799     # 正常关闭连接统计
tcp status timeout      201      # 超时关闭统计
http status 0           75       # http请求失败统计
http status 200         3925     # http响应对应状态码统计

# 连接时长消耗
Connection Time(ms):
            min           mean           max
Connect:   0.005009      0.099203       4.093774      #从连接发起到连接成功
Waiting:   0.010392      0.592263       56.112589     #从http请求数据发送至接收到响应
Process:   0.000003      0.000006       0.000127      #响应数据处理到连接关闭
Total:     0.018885      0.691471       56.125598     #整个连接过程总时常

# 每秒钟的并发数(最小/平均/最大)
Connection succ(c/s):
        min       mean        max
        0       13.382979     37
```