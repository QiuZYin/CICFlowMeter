import csv

from BasicPacketInfo import BasicPacketInfo
from BasicFlow import BasicFlow


class FlowGenerator:
    """重组会话流"""

    def __init__(self, flowTimeout, activityTimeout):

        # 当前正在重组的会话流 <String, BasicFlow>
        self.currentFlows = {}
        # 已经重组好的会话流
        self.finishedFlows = []
        # 流超时
        self.flowTimeout = flowTimeout
        # 流活动超时
        self.flowActivityTimeout = activityTimeout

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
                if flow.packetCount() > 1:
                    self.finishedFlows.append(flow)
                # 该数据包作为新流
                newFlow = BasicFlow(
                    packet=packet,
                    activityTimeout=self.flowActivityTimeout,
                )
                self.currentFlows[flowId] = newFlow
            # 如果该数据包包含FIN标志
            elif packet.hasFlagFIN():
                # 如果是正向数据包
                if flow.getSrcIP() == packet.getSrcIP():
                    # 如果该数据包
                    if flow.setFwdFINFlags() == 1:
                        if flow.getFwdFINFlags() + flow.getBwdFINFlags() == 2:
                            flow.addPacket(packet=packet)
                            self.finishedFlows.append(flow)
                            self.currentFlows.pop(flowId)
                        else:
                            flow.addPacket(packet=packet)
                    else:
                        print(
                            "Forward flow received %d FIN packets"
                            % flow.getFwdFINFlags()
                        )
                else:
                    if flow.setBwdFINFlags() == 1:
                        # FIXME 与上面代码完全相同,可封装
                        if flow.getFwdFINFlags() + flow.getBwdFINFlags() == 2:
                            flow.addPacket(packet=packet)
                            self.finishedFlows.append(flow)
                            self.currentFlows.pop(flowId)
                        else:
                            flow.addPacket(packet=packet)
                    else:
                        print(
                            "Backward flow received %d FIN packets"
                            % flow.getFwdFINFlags()
                        )
            elif packet.hasFlagRST():
                flow.addPacket(packet=packet)
                self.finishedFlows.append(flow)
                self.currentFlows.pop(flowId)
            else:
                if flow.getSrcIP() == packet.getSrcIP() and flow.getFwdFINFlags() == 0:
                    flow.addPacket(packet=packet)

                elif flow.getBwdFINFlags() == 0:
                    flow.addPacket(packet=packet)
                else:
                    print(
                        "FLOW already closed! fwdFIN %d bwdFIN %d"
                        % (flow.getFwdFINFlags(), flow.getBwdFINFlags())
                    )

        else:
            newFlow = BasicFlow(
                packet=packet,
                activityTimeout=self.flowActivityTimeout,
            )
            self.currentFlows[pktFwdFlowId] = newFlow

    def dumpFeature(self):

        with open("test.csv", "w", newline="") as csvfile:
            writer = csv.writer(csvfile)

            # 先写入columns_name
            # writer.writerow(["index", "a_name", "b_name"])

            for flow in self.finishedFlows:

                output = flow.dumpFlowBasedFeatures()

                writer.writerow(output)

    def display(self):
        for flow in self.finishedFlows:
            flow.generateFlowFeatures()
            flow.display()

    def getFinishedFlowsCnt(self):

        return len(self.finishedFlows)


def flowType(flow: BasicFlow) -> BasicFlow:
    return flow
