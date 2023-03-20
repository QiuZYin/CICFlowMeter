class FlowFeature:
    def __init__(self):

        """流基本信息"""
        # 流ID
        self.flowId = None
        # 源IP地址
        self.srcIP = None
        # 目的IP地址
        self.dstIP = None
        # 源端口
        self.srcPort = 0
        # 目的端口
        self.dstPort = 0
        # 传输层协议
        self.protocol = 0

        """数据包个数,负载字节数相关特征"""
        # 流数据包数量
        self.flowPktNum = 0
        # 流负载字节数总和
        self.flowPldByteSum = 0
        # 流负载字节数最大值
        self.flowPldByteMax = 0
        # 流负载字节数最小值
        self.flowPldByteMin = 0
        # 流负载字节数平均值
        self.flowPldByteMean = 0
        # 流负载字节数标准差
        self.flowPldByteStd = 0

        # 正向数据包数量
        self.fwdPktNum = 0
        # 正向数据包负载字节数总和
        self.fwdPldByteSum = 0
        # 正向数据包负载字节数最大值
        self.fwdPldByteMax = 0
        # 正向数据包负载字节数最小值
        self.fwdPldByteMin = 0
        # 正向数据包负载字节数平均值
        self.fwdPldByteMean = 0
        # 正向数据包负载字节数标准差
        self.fwdPldByteStd = 0

        # 反向数据包数量
        self.bwdPktNum = 0
        # 反向数据包负载字节数总和
        self.bwdPldByteSum = 0
        # 反向数据包负载字节数最大值
        self.bwdPldByteMax = 0
        # 反向数据包负载字节数最小值
        self.bwdPldByteMin = 0
        # 反向数据包负载字节数平均值
        self.bwdPldByteMean = 0
        # 反向数据包负载字节数标准差
        self.bwdPldByteStd = 0

        """数据包头字节数相关特征"""
        # 正向数据包头字节数最大值
        self.fwdHeadByteMax = 0
        # 正向数据包头字节数最小值
        self.fwdHeadByteMin = 0
        # 正向数据包头字节数平均值
        self.fwdHeadByteMean = 0
        # 正向数据包头字节数标准差
        self.fwdHeadByteStd = 0

        # 反向数据包头字节数最大值
        self.bwdHeadByteMax = 0
        # 反向数据包头字节数最小值
        self.bwdHeadByteMin = 0
        # 反向数据包头字节数平均值
        self.bwdHeadByteMean = 0
        # 反向数据包头字节数标准差
        self.bwdHeadByteStd = 0

        """流速相关特征"""
        # 流持续时间(ms)
        self.flowDurationMS = 0

        # 每秒传输的数据包数
        self.flowPktsS = 0
        # 每毫秒传输的数据包字节数
        self.flowPldBytesMS = 0

        # 每秒正向传输的数据包数
        self.fwdPktsS = 0
        # 每毫秒正向传输的数据包字节数
        self.fwdPldBytesMS = 0

        # 每秒反向传输的数据包数
        self.bwdPktsS = 0
        # 每毫秒反向传输的数据包字节数
        self.bwdPldBytesMS = 0

        # 反向/正向传输的数据包数比例
        self.pktsRatio = 0
        # 反向/正向传输的字节数比例
        self.bytesRatio = 0

        """间隔时间相关特征"""
        # 数据包间隔时间最大值
        self.flowIatMax = 0
        # 数据包间隔时间最小值
        self.flowIatMin = 0
        # 数据包间隔时间平均值
        self.flowIatMean = 0
        # 数据包间隔时间标准差
        self.flowIatStd = 0

        # 正向数据包间隔时间最大值
        self.fwdIatMax = 0
        # 正向数据包间隔时间最小值
        self.fwdIatMin = 0
        # 正向数据包间隔时间平均值
        self.fwdIatMean = 0
        # 正向数据包间隔时间标准差
        self.fwdIatStd = 0

        # 反向数据包间隔时间最大值
        self.bwdIatMax = 0
        # 反向数据包间隔时间最小值
        self.bwdIatMin = 0
        # 反向数据包间隔时间平均值
        self.bwdIatMean = 0
        # 反向数据包间隔时间标准差
        self.bwdIatStd = 0

        """TCP标志相关特征"""
        # 带有FIN的数据包数量
        self.FINcnt = 0
        # 带有SYN的数据包数量
        self.SYNcnt = 0
        # 带有RST的数据包数量
        self.RSTcnt = 0
        # 带有PSH的数据包数量
        self.PSHcnt = 0
        # 带有ACK的数据包数量
        self.ACKcnt = 0
        # 带有URG的数据包数量
        self.URGcnt = 0
        # 带有ECE的数据包数量
        self.ECEcnt = 0
        # 带有CWR的数据包数量
        self.CWRcnt = 0

        # 正向数据包中设置PSH标志的数量(UDP为0)
        self.fwdPSHcnt = 0
        # 反向数据包中设置PSH标志的数量(UDP为0)
        self.bwdPSHcnt = 0
        # 正向数据包中设置URG标志的数量(UDP为0)
        self.fwdURGcnt = 0
        # 反向数据包中设置URG标志的数量(UDP为0)
        self.bwdURGcnt = 0

        """初始窗口大小"""
        # 正向的初始TCP窗口大小(UDP为0)
        self.fwdInitWinBytes = 0
        # 反向的初始TCP窗口大小(UDP为0)
        self.bwdInitWinBytes = 0

        """有效负载数据包个数"""
        # 具有有效负载的正向数据包个数
        self.fwdPktsWithPayload = 0
        # 具有有效负载的反向数据包个数
        self.bwdPktsWithPayload = 0

        """子流相关特征"""
        # 正向子流中数据包的平均数量
        self.subFlowFwdPkts = 0
        # 正向子流中字节的平均数量
        self.subFlowFwdPldBytes = 0
        # 反向子流中数据包的平均数量
        self.subFlowBwdPkts = 0
        # 反向子流中字节的平均数量
        self.subFlowBwdPldBytes = 0

        """流活动-空闲相关特征"""
        # 流在空闲之前处于活动状态的时间总和
        self.flowActSum = 0
        # 流在空闲之前处于活动状态的时间最大值
        self.flowActMax = 0
        # 流在空闲之前处于活动状态的时间最小值
        self.flowActMin = 0
        # 流在空闲之前处于活动状态的时间平均值
        self.flowActMean = 0
        # 流在空闲之前处于活动状态的时间标准差
        self.flowActStd = 0

        # 流在激活之前处于空闲状态的时间总和
        self.flowIdleSum = 0
        # 流在激活之前处于空闲状态的时间最大值
        self.flowIdleMax = 0
        # 流在激活之前处于空闲状态的时间最小值
        self.flowIdleMin = 0
        # 流在激活之前处于空闲状态的时间平均值
        self.flowIdleMean = 0
        # 流在激活之前处于空闲状态的时间标准差
        self.flowIdleStd = 0

        """Bulk相关特征"""
        # 正向每批量的平均数据包数
        self.fwdAvgPktsPerBulk = 0
        # 正向每批量的平均字节数
        self.fwdAvgBytesPerBulk = 0
        # 正向平均bulk速率
        self.fwdAvgBulkRate = 0
        # 反向每批量的平均数据包数
        self.bwdAvgPktsPerBulk = 0
        # 反向每批量的平均字节数
        self.bwdAvgBytesPerBulk = 0
        # 反向平均bulk速率
        self.bwdAvgBulkRate = 0

    def calRate(self):
        if self.flowDurationMS > 0:
            self.flowPktsS = self.flowPktNum / (self.flowDurationMS / 1000)
            self.flowPldBytesMS = self.flowPldByteSum / self.flowDurationMS
            self.fwdPktsS = self.fwdPktNum / (self.flowDurationMS / 1000)
            self.fwdPldBytesMS = self.fwdPldByteSum / self.flowDurationMS
            self.bwdPktsS = self.bwdPktNum / (self.flowDurationMS / 1000)
            self.bwdPldBytesMS = self.bwdPldByteSum / self.flowDurationMS

        if self.fwdPktNum > 0:
            self.pktsRatio = self.bwdPktNum / self.fwdPktNum
        if self.fwdPldByteSum > 0:
            self.bytesRatio = self.bwdPldByteSum / self.fwdPldByteSum

    def calSubFlow(self, subFlowcnt):
        self.subFlowFwdPkts = self.fwdPktNum / subFlowcnt
        self.subFlowFwdPldBytes = self.fwdPldByteSum / subFlowcnt
        self.subFlowBwdPkts = self.bwdPktNum / subFlowcnt
        self.subFlowBwdPldBytes = self.bwdPldByteSum / subFlowcnt

    def listAllMember(self):
        for name, value in vars(self).items():
            print("%s = %s" % (name, value))
