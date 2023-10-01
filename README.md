# OneAgent
   实现操作系统侧主要Promethus采集器的整合
# 1、进展
   实现进程、网络链接、脚本采集功能
# 2、使用方法
  go build  
  ./OneAgent  
  使用http://localhost:9172/metrics进行访问
# 3、指标说明
  返回数据并未严格按照普米每个指标值一行的方式进行输出，而是在Label中进行指标值，如进程的CPU等，如使用普米采集器需要做处理。这样做的原因是由于进程和网络链接的信息量远远大于主机内其他信息，所以采用这种模式解决普米格式不支持多指标的问题（Influx Line Protocol更好）
# 4、说明
1、进程和监控端口的对应关系
进程A在22端口监听，连接到22端口的链接是在子进程B中，这个和Linux操作系统的进程模型有关系。  
2、表结构说明
process_host_info process=1表示全量获取进程信息，0表示增量进程信息
network_host_info network=1表示全量获取进程信息，0表示增量进程信息
# 5、配置说明
"process":{  
        "interval": 10,//定义全量扫描的间隔秒数，建议周期为86400（1天）  
        "cpuOffset": 30,//当CPU变化量超过此值时发送进程信息，建议30  
        "memoryOffset": 200000000,//当内存字节数变化量超过此值时发送进程信息，建议200MB  
        "ioSpeedPerSecond": 5000000,//当读写速度每秒字节数变化量超过此值时发送进程信息，建议30  
        "openFileOffset": 100,//当打开文件变化量超过此值时发送进程信息，建议100  
        "threadOffset": 30,//当线程数变化量超过此值时发送进程信息，建议30  
        "localLog":true //  
    },  
    "network":{  
        "interval": 10,//定义全量扫描的间隔秒数，  建议周期为86400    
        "counterOffset":100,//当进程连接数变化量超过此值时发送网络连接信息，建议30  
        "localLog":true  
    }  