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
