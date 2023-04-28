import time

from utils import SummaryStatistics, BulkStatistics
from BasicPacketInfo import BasicPacketInfo
from FlowFeature import FlowFeature


class BasicFlow:
    """会话流的统一格式"""

    def __init__(
        self,
        packet: BasicPacketInfo,
        activityTimeout=5000000,
        subFlowTimeout=1000000,
        bulkTimeout=1000000,
        flowSrc=None,
        flowDst=None,
        flowSrcPort=None,
        flowDstPort=None,
    ):

        """流标识信息"""
        # 流ID
        self.flowId = None

        """流基本信息"""
        # 源IP地址
        self.srcIP = None
        # 源端口
        self.srcPort = 0
        # 目的IP地址
        self.dstIP = None
        # 目的端口
        self.dstPort = 0
        # 传输层协议(TCP:6 UDP:17)
        self.protocol = 0

        """流时间信息"""
        # 流开始时间
        self.flowStartTime = 0
        # 流最近出现时间
        self.flowLastTime = 0

        # 正向数据包最近出现时间
        self.fwdLastTime = 0
        # 反向数据包最近出现时间
        self.bwdLastTime = 0

        # 子流时间戳
        self.subFlowLastTime = 0
        # 子流个数
        self.subFlowcnt = 0
        # 子流超时
        self.subFlowTimeout = 0

        # 流开始活动时间
        self.startActiveTime = 0
        # 流结束活动时间
        self.endActiveTime = 0
        # 流活动超时
        self.activityTimeout = 0

        # 数据包间隔时间列表(ms)
        self.flowIAT = SummaryStatistics()
        # 正向数据包间隔时间列表(ms)
        self.forwardIAT = SummaryStatistics()
        # 反向数据包间隔时间列表(ms)
        self.backwardIAT = SummaryStatistics()
        # 流活动时间列表(ms)
        self.flowActive = SummaryStatistics()
        # 流空闲时间列表(ms)
        self.flowIdle = SummaryStatistics()

        """数据包长度信息"""
        # 正向数据包头长度列表
        self.fwdHeadStats = SummaryStatistics()
        # 反向数据包头长度列表
        self.bwdHeadStats = SummaryStatistics()

        # 正向数据包负载长度列表
        self.fwdPktPldStats = SummaryStatistics()
        # 反向数据包负载长度列表
        self.bwdPktPldStats = SummaryStatistics()
        # 数据包负载长度列表
        self.flowPldStats = SummaryStatistics()

        """TCP标志信息"""
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
        # 正向数据包中设置FIN标志的数量(UDP为0)
        self.fwdFINcnt = 0
        # 反向数据包中设置FIN标志的数量(UDP为0)
        self.bwdFINcnt = 0

        """Bulk相关信息"""
        # 正向Bulk统计特征
        self.fwdBulkStats = BulkStatistics()
        # 反向Bulk统计特征
        self.bwdBulkStats = BulkStatistics()

        """部分统计特征"""
        # 正向的初始TCP窗口大小(UDP为0)
        self.fwdInitWinBytes = 0
        # 反向的初始TCP窗口大小(UDP为0)
        self.bwdInitWinBytes = 0
        # 具有有效负载的正向数据包个数
        self.fwdPktsWithPayload = 0
        # 具有有效负载的反向数据包个数
        self.bwdPktsWithPayload = 0

        """会话流统计特征类"""
        # 基于流的统计特征
        self.features = FlowFeature()

        """会话流传输层负载信息"""
        # 正向数据包负载信息
        self.fwdPayloads = []
        # 反向数据包负载信息
        self.bwdPayloads = []

        """根据参数以及第一个数据包 初始化部分信息"""
        # 优先根据参数设置
        if flowSrc != None and flowSrcPort != None:
            self.srcIP = flowSrc
            self.srcPort = flowSrcPort
        else:
            self.srcIP = packet.getSrcIP()
            self.srcPort = packet.getSrcPort()

        if flowDst != None and flowDstPort != None:
            self.dstIP = flowDst
            self.dstPort = flowDstPort
        else:
            self.dstIP = packet.getDstIP()
            self.dstPort = packet.getDstPort()

        # 设置流ID
        self.flowId = packet.getFwdFlowId()
        self.protocol = packet.getProtocol()

        # 获取数据包时间戳
        currentTS = packet.getTimeStamp()
        # 设置会话流开始时间等信息
        self.flowStartTime = currentTS
        self.flowLastTime = currentTS
        self.startActiveTime = currentTS
        self.endActiveTime = currentTS

        # 设置阈值
        self.subFlowTimeout = subFlowTimeout
        self.activityTimeout = activityTimeout
        self.bulkTimeout = bulkTimeout

        # 向会话流中添加数据包
        self.addPacket(packet)

    def addPacket(self, packet: BasicPacketInfo):
        """
        Description: 向会话流中添加数据包
        Input: BasicPacketInfo
        Output: None
        """

        # 获取数据包时间戳
        currentTS = packet.getTimeStamp()
        # 获取负载长度
        pktPLBs = packet.getPayloadBytes()

        # 如果是正向流
        if self.srcIP == packet.getSrcIP():

            # 更新正向数据包头长度
            self.fwdHeadStats.addValue(packet.getHeadBytes())
            # 更新正向数据包负载长度
            self.fwdPktPldStats.addValue(pktPLBs)
            # 更新正向TCP标志
            self.fwdPSHcnt += packet.hasFlagPSH()
            self.fwdURGcnt += packet.hasFlagURG()

            # 如果负载不为空
            if pktPLBs > 0:
                # 更新有效负载的正向数据包个数
                self.fwdPktsWithPayload += 1
                # 更新正向数据包负载
                self.fwdPayloads.append(packet.getPayload())

            # 如果是第一个正向数据包
            if self.fwdPktPldStats.getN() == 1:
                # 设置正向的初始TCP窗口大小
                self.fwdInitWinBytes = packet.getTCPWindow()
            else:  # 否则
                # 更新正向数据包间隔时间
                self.forwardIAT.addValue((currentTS - self.fwdLastTime) / 1000)

            # 更新正向数据包当前时间
            self.fwdLastTime = currentTS

            # 更新Bulk相关信息
            self.updateFlowBulk(
                packet,
                self.fwdBulkStats,
                self.bwdBulkStats.lastTS,
            )
        # 如果是反向流
        elif self.srcIP == packet.getDstIP():

            # 更新反向数据包头长度
            self.bwdHeadStats.addValue(packet.getHeadBytes())
            # 更新反向数据包负载长度
            self.bwdPktPldStats.addValue(pktPLBs)
            # 更新反向TCP标志
            self.bwdPSHcnt += packet.hasFlagPSH()
            self.bwdURGcnt += packet.hasFlagURG()

            # 如果负载不为空
            if pktPLBs > 0:
                # 更新有效负载的反向数据包个数
                self.bwdPktsWithPayload += 1
                # 更新反向数据包负载
                self.bwdPayloads.append(packet.getPayload())

            # 如果是第一个反向数据包
            if self.bwdPktPldStats.getN() == 1:
                # 设置反向的初始TCP窗口大小
                self.bwdInitWinBytes = packet.getTCPWindow()
            else:  # 否则
                # 更新反向数据包间隔时间
                self.backwardIAT.addValue((currentTS - self.bwdLastTime) / 1000)

            # 更新反向数据包当前时间
            self.bwdLastTime = currentTS

            # 更新Bulk相关信息
            self.updateFlowBulk(
                packet,
                self.bwdBulkStats,
                self.fwdBulkStats.lastTS,
            )
        # 否则报错
        else:
            print("ERROR")

        # 更新会话流数据包负载长度
        self.flowPldStats.addValue(pktPLBs)

        # 如果不是第一个数据包
        if self.flowPldStats.getN() > 1:
            # 更新会话流数据包间隔时间
            self.flowIAT.addValue((currentTS - self.flowLastTime) / 1000)

        # 更新当前时间
        self.flowLastTime = currentTS

        # 更新标志信息
        self.checkFlags(packet)
        # 更新子流信息
        self.updateSubflows(packet)
        # 更新流活动空闲信息
        self.updateActIdleTime(packet)

    def checkFlags(self, packet: BasicPacketInfo):
        """
        Description: 检查数据包TCP标志数量,并进行更新
        Input: BasicPacketInfo
        Output: None
        """
        self.FINcnt += packet.hasFlagFIN()
        self.SYNcnt += packet.hasFlagSYN()
        self.RSTcnt += packet.hasFlagRST()
        self.PSHcnt += packet.hasFlagPSH()
        self.ACKcnt += packet.hasFlagACK()
        self.URGcnt += packet.hasFlagURG()
        self.ECEcnt += packet.hasFlagECE()
        self.CWRcnt += packet.hasFlagCWR()

    def updateSubflows(self, packet: BasicPacketInfo):
        """
        Description: 更新子流时间戳和个数
        Input: BasicPacketInfo
        Output: None
        """
        # 当前时间戳
        currentTS = packet.getTimeStamp()
        # 和上一个数据包的间隔时间
        idleTime = currentTS - self.subFlowLastTime
        # 如果超过阈值
        if idleTime > self.subFlowTimeout:
            # 子流数量加一
            self.subFlowcnt += 1
        # 更新子流时间戳
        self.subFlowLastTime = currentTS

    def updateActIdleTime(self, packet: BasicPacketInfo):
        """
        Description: 统计流活动时间和空闲时间
        Input: BasicPacketInfo
        Output: None
        """
        # 当前时间戳
        currentTS = packet.getTimeStamp()
        # 和上一个数据包的间隔时间(即空闲时间)
        idleTime = currentTS - self.endActiveTime
        # 如果超过阈值
        if idleTime > self.activityTimeout:

            # 更新流空闲时间
            self.flowIdle.addValue(idleTime / 1000)

            # 计算流活动时间
            activeTime = self.endActiveTime - self.startActiveTime
            # 如果活动时间大于0(即上一个活动区间的数据包个数大于1)
            if activeTime > 0:
                # 更新流活动时间
                self.flowActive.addValue(activeTime / 1000)

            # 更新流活动开始时间
            self.startActiveTime = currentTS

        # 更新流活动结束时间
        self.endActiveTime = currentTS

    def updateFlowBulk(
        self, packet: BasicPacketInfo, bulkStats: BulkStatistics, lastTSinOther
    ):
        """
        Description: 更新Bulk相关信息
        Input: BasicPacketInfo, BulkStatistics, lastTSinOther
        Output: None
        """
        # 数据包负载长度
        payloadBytes = packet.getPayloadBytes()
        # 当前时间戳
        currentTS = packet.getTimeStamp()

        # 若负载为空,则返回
        if payloadBytes == 0:
            return

        # 若   另一个流向的最后一个负载不为空数据包的时间戳 大于 当前流向bulk的开始时间戳
        # 或者 当前bulk的开始时间戳 等于 零
        # 或者 当前时间戳 - 当前bulk的最后一个时间戳 大于 bulk阈值
        if (
            lastTSinOther > bulkStats.startTS
            or bulkStats.startTS == 0
            or currentTS - bulkStats.lastTS > self.bulkTimeout
        ):
            # 数据包缓存数量 设为 1
            bulkStats.pktsCache = 1
            # 缓存字节数 设为 负载字节数
            bulkStats.bytesCache = payloadBytes
            # 设置 Bulk数据包开始时间戳
            bulkStats.startTS = currentTS
        else:  # 否则
            # 更新数据包缓存数量
            bulkStats.pktsCache += 1
            # 更新缓存字节数
            bulkStats.bytesCache += payloadBytes

            # 若数据包缓存数量 等于 4
            if bulkStats.pktsCache == 4:
                # 更新 Bulk数量
                bulkStats.cnts += 1
                # 更新 Bulk数据包数量
                bulkStats.pkts += 4
                # 更新 Bulk字节数
                bulkStats.bytes += bulkStats.bytesCache
                # 更新 Bulk持续时间
                bulkStats.duration += currentTS - bulkStats.startTS
            # 若数据包缓存数量 大于 4
            elif bulkStats.pktsCache > 4:
                # 更新 Bulk数据包数量
                bulkStats.pkts += 1
                # 更新 Bulk字节数
                bulkStats.bytes += payloadBytes
                # 更新 Bulk持续时间
                bulkStats.duration += currentTS - bulkStats.lastTS

        # 更新Bulk结束时间
        bulkStats.lastTS = currentTS

    def endSession(self):
        """
        Description: 结束会话,更新流活动时间
        Input: None
        Output: None
        """
        # 计算活动时间
        activeTime = self.endActiveTime - self.startActiveTime
        # 如果活动时间大于0
        if activeTime > 0:
            # 更新流活动时间
            self.flowActive.addValue(activeTime / 1000)

    def generateFlowFeatures(self):

        """流基本信息"""
        self.features.flowId = self.flowId
        self.features.srcIP = self.srcIP
        self.features.srcPort = self.srcPort
        self.features.dstIP = self.dstIP
        self.features.dstPort = self.dstPort
        self.features.protocol = self.protocol

        """数据包个数,负载字节数,包头字节数相关特征"""
        # 会话流负载长度信息
        self.features.flowPktNum = self.flowPldStats.getN()
        self.features.flowPldByteSum = self.flowPldStats.getSum()
        self.features.flowPldByteMax = self.flowPldStats.getMax()
        self.features.flowPldByteMin = self.flowPldStats.getMin()
        self.features.flowPldByteMean = self.flowPldStats.getMean()
        self.features.flowPldByteStd = self.flowPldStats.getStd()

        # 正向流负载长度信息
        if self.fwdPktPldStats.getN() > 0:
            self.features.fwdPktNum = self.fwdPktPldStats.getN()

            self.features.fwdPldByteSum = self.fwdPktPldStats.getSum()
            self.features.fwdPldByteMax = self.fwdPktPldStats.getMax()
            self.features.fwdPldByteMin = self.fwdPktPldStats.getMin()
            self.features.fwdPldByteMean = self.fwdPktPldStats.getMean()
            self.features.fwdPldByteStd = self.fwdPktPldStats.getStd()

            self.features.fwdHeadByteMax = self.fwdHeadStats.getMax()
            self.features.fwdHeadByteMin = self.fwdHeadStats.getMin()
            self.features.fwdHeadByteMean = self.fwdHeadStats.getMean()
            self.features.fwdHeadByteStd = self.fwdHeadStats.getStd()

        # 反向流负载长度信息
        if self.bwdPktPldStats.getN() > 0:
            self.features.bwdPktNum = self.bwdPktPldStats.getN()

            self.features.bwdPldByteSum = self.bwdPktPldStats.getSum()
            self.features.bwdPldByteMax = self.bwdPktPldStats.getMax()
            self.features.bwdPldByteMin = self.bwdPktPldStats.getMin()
            self.features.bwdPldByteMean = self.bwdPktPldStats.getMean()
            self.features.bwdPldByteStd = self.bwdPktPldStats.getStd()

            self.features.bwdHeadByteMax = self.bwdHeadStats.getMax()
            self.features.bwdHeadByteMin = self.bwdHeadStats.getMin()
            self.features.bwdHeadByteMean = self.bwdHeadStats.getMean()
            self.features.bwdHeadByteStd = self.bwdHeadStats.getStd()

        """流速相关特征"""
        # 流持续时间
        self.features.flowDurationMS = (self.flowLastTime - self.flowStartTime) / 1000
        # 速率相关特征
        self.features.calRate()

        """间隔时间相关特征"""
        # 会话流间隔时间
        if self.flowIAT.getN() > 0:
            self.features.flowIatMax = self.flowIAT.getMax()
            self.features.flowIatMin = self.flowIAT.getMin()
            self.features.flowIatMean = self.flowIAT.getMean()
            self.features.flowIatStd = self.flowIAT.getStd()

        # 正向流间隔时间
        if self.forwardIAT.getN() > 0:
            self.features.fwdIatMax = self.forwardIAT.getMax()
            self.features.fwdIatMin = self.forwardIAT.getMin()
            self.features.fwdIatMean = self.forwardIAT.getMean()
            self.features.fwdIatStd = self.forwardIAT.getStd()

        # 反向流间隔时间
        if self.backwardIAT.getN() > 0:
            self.features.bwdIatMax = self.backwardIAT.getMax()
            self.features.bwdIatMin = self.backwardIAT.getMin()
            self.features.bwdIatMean = self.backwardIAT.getMean()
            self.features.bwdIatStd = self.backwardIAT.getStd()

        """TCP标志相关特征"""
        self.features.FINcnt = self.FINcnt
        self.features.SYNcnt = self.SYNcnt
        self.features.RSTcnt = self.RSTcnt
        self.features.PSHcnt = self.PSHcnt
        self.features.ACKcnt = self.ACKcnt
        self.features.URGcnt = self.URGcnt
        self.features.ECEcnt = self.ECEcnt
        self.features.CWRcnt = self.CWRcnt

        self.features.fwdPSHcnt = self.fwdPSHcnt
        self.features.bwdPSHcnt = self.bwdPSHcnt
        self.features.fwdURGcnt = self.fwdURGcnt
        self.features.bwdURGcnt = self.bwdURGcnt

        """初始窗口大小"""
        self.features.fwdInitWinBytes = self.fwdInitWinBytes
        self.features.bwdInitWinBytes = self.bwdInitWinBytes

        """有效负载数据包个数"""
        self.features.fwdPktsWithPayload = self.fwdPktsWithPayload
        self.features.bwdPktsWithPayload = self.bwdPktsWithPayload

        """子流相关特征"""
        self.features.calSubFlow(self.subFlowcnt)

        """流活动-空闲相关特征"""
        # 会话流活动时间信息
        if self.flowActive.getN() > 0:
            self.features.flowActSum = self.flowActive.getSum()
            self.features.flowActMax = self.flowActive.getMax()
            self.features.flowActMin = self.flowActive.getMin()
            self.features.flowActMean = self.flowActive.getMean()
            self.features.flowActStd = self.flowActive.getStd()

        # 会话流空闲时间信息
        if self.flowIdle.getN() > 0:
            self.features.flowIdleSum = self.flowIdle.getSum()
            self.features.flowIdleMax = self.flowIdle.getMax()
            self.features.flowIdleMin = self.flowIdle.getMin()
            self.features.flowIdleMean = self.flowIdle.getMean()
            self.features.flowIdleStd = self.flowIdle.getStd()

        """Bulk相关特征"""
        # 正向Bulk相关信息
        if self.fwdBulkStats.cnts > 0:
            self.features.fwdAvgPktsPerBulk = (
                self.fwdBulkStats.pkts / self.fwdBulkStats.cnts
            )
            self.features.fwdAvgBytesPerBulk = (
                self.fwdBulkStats.bytes / self.fwdBulkStats.cnts
            )
        if self.fwdBulkStats.duration > 0:
            self.features.fwdAvgBulkS = self.fwdBulkStats.cnts / (
                self.fwdBulkStats.duration / 1000000
            )

        # 反向Bulk相关信息
        if self.bwdBulkStats.cnts > 0:
            self.features.bwdAvgPktsPerBulk = (
                self.bwdBulkStats.pkts / self.bwdBulkStats.cnts
            )
            self.features.bwdAvgBytesPerBulk = (
                self.bwdBulkStats.bytes / self.bwdBulkStats.cnts
            )
        if self.bwdBulkStats.duration > 0:
            self.features.bwdAvgBulkS = self.bwdBulkStats.cnts / (
                self.bwdBulkStats.duration / 1000000
            )

        # 通过FlowFeature类返回特征
        return self.features.returnFeature()

    def getFwdPayloads(self):
        """返回正向数据包负载信息"""
        return self.fwdPayloads

    def getBwdPayloads(self):
        """返回反向数据包负载信息"""
        return self.bwdPayloads

    def getSrcIP(self):
        return self.srcIP

    def getFlowLastTime(self):
        return self.flowLastTime

    def getPktCnt(self):
        return self.flowPldStats.getN()

    def setFwdFINFlags(self):
        self.fwdFINcnt += 1

    def setBwdFINFlags(self):
        self.bwdFINcnt += 1

    def getFwdFINFlags(self):
        return self.fwdFINcnt

    def getBwdFINFlags(self):
        return self.bwdFINcnt
