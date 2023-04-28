import csv

from BasicPacketInfo import BasicPacketInfo
from BasicFlow import BasicFlow
import FlowFeature


class FlowGenerator:
    """重组会话流"""

    def __init__(self, flowTimeout, activityTimeout, subFlowTimeout, bulkTimeout):

        # 当前正在重组的会话流 <String, BasicFlow>
        self.currentFlows = {}
        # 已经重组好的会话流
        self.finishedFlows = []
        # 流超时
        self.flowTimeout = flowTimeout
        # 活动超时
        self.activityTimeout = activityTimeout
        # 子流超时
        self.subFlowTimeout = subFlowTimeout
        # bulk超时
        self.bulkTimeout = bulkTimeout

    def addPacket(self, packet: BasicPacketInfo):

        if packet == None:
            return

        # 数据包时间戳
        currentTS = packet.getTimeStamp()
        # 数据包正向流ID
        pktFwdFlowId = packet.getFwdFlowId()
        # 数据包反向流ID
        pktBwdFlowId = packet.getBwdFlowId()

        # 如果其中一个流ID在当前重组流字典中
        if (pktFwdFlowId in self.currentFlows) or (pktBwdFlowId in self.currentFlows):
            # 确定流ID
            if pktFwdFlowId in self.currentFlows:
                flowId = pktFwdFlowId
            else:
                flowId = pktBwdFlowId

            # FIXME 指明数据类型,有代码提示
            flow = flowType(self.currentFlows[flowId])

            # 如果和上一个数据包的间隔时间超过两分钟,那么认为这是一个新流
            if currentTS - flow.getFlowLastTime() > self.flowTimeout:
                # 若流中数据包个数大于1,则添加到已完成的流列表
                if flow.getPktCnt() > 1:
                    flow.endSession()
                    self.finishedFlows.append(flow)
                # 该数据包作为新流
                newFlow = BasicFlow(
                    packet=packet,
                    activityTimeout=self.activityTimeout,
                    subFlowTimeout=self.subFlowTimeout,
                    bulkTimeout=self.bulkTimeout,
                )
                self.currentFlows[flowId] = newFlow

                if len(self.finishedFlows) % 100 == 0:
                    print(len(self.finishedFlows))

            # 如果包含RST标志,则直接结束会话
            elif packet.hasFlagRST():

                flow.addPacket(packet=packet)
                flow.endSession()
                self.finishedFlows.append(flow)
                self.currentFlows.pop(flowId)

                if len(self.finishedFlows) % 100 == 0:
                    print(len(self.finishedFlows))

            # 如果正反向各有1个FIN标志,那么这是最后一个ACK包,结束会话
            elif flow.getFwdFINFlags() == 1 and flow.getBwdFINFlags() == 1:

                flow.addPacket(packet=packet)

                # 如果负载等于0,则表明这是ACK包
                if packet.getPayloadBytes() == 0:
                    flow.endSession()
                    self.finishedFlows.append(flow)
                    self.currentFlows.pop(flowId)

                    if len(self.finishedFlows) % 100 == 0:
                        print(len(self.finishedFlows))

            # 否则加入到流中
            else:
                flow.addPacket(packet=packet)
                # 如果该数据包包含FIN标志
                if packet.hasFlagFIN():
                    # 统计正反向FIN标志个数
                    if flow.getSrcIP() == packet.getSrcIP():
                        flow.setFwdFINFlags()
                    else:
                        flow.setBwdFINFlags()
        else:
            newFlow = BasicFlow(
                packet=packet,
                activityTimeout=self.activityTimeout,
                subFlowTimeout=self.subFlowTimeout,
                bulkTimeout=self.bulkTimeout,
            )
            self.currentFlows[pktFwdFlowId] = newFlow

    def clearFlow(self):
        # 将剩余会话流加入到已完成列表
        for flow in self.currentFlows.values():
            # FIXME 指明数据类型,有代码提示
            flow = flowType(flow)
            flow.endSession()
            self.finishedFlows.append(flow)
        # 清空字典
        self.currentFlows.clear()

    def dumpFeatureToCSV(self):
        # 将流量统计特征保存到CSV文件
        with open("test.csv", "w", newline="") as csvfile:
            writer = csv.writer(csvfile)

            # 写入特征名称
            columns_name = FlowFeature.getCsvColName()
            writer.writerow(columns_name)

            # 写入所有会话流的特征值
            for flow in self.finishedFlows:
                # FIXME 指明数据类型,有代码提示
                flow = flowType(flow)
                output = flow.generateFlowFeatures()
                writer.writerow(output)

    def dumpPayloadToCSV(self):

        with open("payload.csv", "w", newline="") as csvfile:
            writer = csv.writer(csvfile)

            # 写入所有会话流的负载数据
            for flow in self.finishedFlows:
                # FIXME 指明数据类型,有代码提示
                flow = flowType(flow)
                output = flow.generateFlowFeatures()
                writer.writerow(output)


def flowType(flow: BasicFlow) -> BasicFlow:
    return flow
