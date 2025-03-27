这是一个用于扫描证书日志的小工具
基于下面连接改编：
https://github.com/google/certificate-transparency-go

requirement
go 1.23

主函数为
./scanner/scanlog/scanlog.go

功能：
扫描google的某个证书日志服务器，从中提取域名，用于下一步分析

安装：
go build ./scanner/scanlog
对主函数可以进行修改，修改完之后go build即可

用法：
./scanlog -h
./scanlog --log_uri https://ct.googleapis.com/logs/argon2020 --batch_size 10 --num_workers 1  (常用用法)

会在当前目录下面创建子目录./scan_results
所有扫描得到的证书域名信息会以json文件，每1000条存一个json
