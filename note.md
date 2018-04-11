- RTT(Round-Trip Time) 往返时间
- RTO(retransmission timeout)超时重传机制
-
- conv 会话ID
- mtu	最大传输单元
- mss	最大分片大小
- state 连接状态（0xFFFFFFFF表示断开连接）
- snd_una 第一个未确认的包
- snd_nxt	待发送包的序号
- rcv_nxt 待接收消息序号
- ssthresh 拥塞窗口阈值
- rx_rttvar	ack接收rtt浮动值
- rx_srtt ack接收rtt静态值
- rx_rto	由ack接收延迟计算出来的复原时间
- rx_minrto 最小复原时间
- snd_wnd	发送窗口大小
- rcv_wnd	接收窗口大小
- rmt_wnd	远端接收窗口大小
- cwnd	拥塞窗口大小
- probe 探查变量
    - IKCP_ASK_TELL表示告知远端窗口大小。
    - IKCP_ASK_SEND表示请求远端告知窗口大小
- interval	内部flush刷新间隔
- ts_flush 下次flush刷新时间戳
- nodelay	是否启动无延迟模式
- updated 是否调用过update函数的标识
- ts_probe,	下次探查窗口的时间戳
- probe_wait 探查窗口需要等待的时间
- dead_link	最大重传次数
- incr 可发送的最大数据量
- 
- fastresend 触发快速重传的重复ack个数
- nocwnd	取消拥塞控制
- stream 是否采用流传输模式
- 
- snd_queue	发送消息的队列
- rcv_queue	接收消息的队列
- snd_buf 发送消息的缓存
- rcv_buf 接收消息的缓存
- acklist 待发送的ack列表
- buffer 存储消息字节流的内存
- output udp发送消息的回调函数

#### [KCP 实现](https://github.com/kaiywen/kaiywen.github.io/blob/24c00456004ec7183ab072501311a79b39142f9d/_posts/2017-07-30-KCP%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90.md)

1. 设置底层的输出函数 kcp->output = udp_output;
2. 上层应用可以调用ikcp_send来发送数据,数据将会进入到snd_queue中
3. 下层函数ikcp_flush将会决定将多少数据从snd_queue中移到snd_buf中，进行发送
4. kcp->output() 发送


1. kcp->ikcp_input() 从底层接受数据到rcv_buf中
2. ikcp_recv 为上层调用的接口 
   1. 将rcv_buf中的数据转移到rcv_queue
   2. 将数据从rcv_queue中移动到应用层buffer中
3. 