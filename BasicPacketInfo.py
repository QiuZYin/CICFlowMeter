class BasicPacketInfo:
    """数据包的统一格式"""

    def __init__(
        self,
        generator,
        srcIP,
        dstIP,
        srcPort,
        dstPort,
        protocol,
        timeStamp,
        headBytes,
        payloadBytes,
        flags,
        TCPWindow,
        payload,
    ):
        # 数据包编号
        self.id = generator.nextId()
        # 源IP地址
        self.srcIP = srcIP
        # 目的IP地址
        self.dstIP = dstIP
        # 源端口
        self.srcPort = srcPort
        # 目的端口
        self.dstPort = dstPort
        # 传输层协议(TCP:6 UDP:17)
        self.protocol = protocol
        # 时间戳
        self.timeStamp = timeStamp
        # 传输层数据包头长度
        self.headBytes = headBytes
        # 负载长度
        self.payloadBytes = payloadBytes
        # TCP控制位
        self.flags = flags
        # TCP窗口大小
        self.TCPWindow = TCPWindow
        # 负载
        self.payload = payload
        # 所属流编号
        self.fwdFlowId = self.generateFlowId(True)
        self.bwdFlowId = self.generateFlowId(False)

    def generateFlowId(self, forward: bool) -> str:
        """
        Description: 生成数据包的流ID
        Input: 是否为正向流
        Output: 流ID
        """
        if forward:
            flowId = (
                self.srcIP
                + "-"
                + str(self.srcPort)
                + "-"
                + self.dstIP
                + "-"
                + str(self.dstPort)
            )
        else:
            flowId = (
                self.dstIP
                + "-"
                + str(self.dstPort)
                + "-"
                + self.srcIP
                + "-"
                + str(self.srcPort)
            )
        return flowId

    def getSrcIP(self) -> str:
        return self.srcIP

    def getDstIP(self) -> str:
        return self.dstIP

    def getSrcPort(self) -> int:
        return self.srcPort

    def getDstPort(self) -> int:
        return self.dstPort

    def getProtocol(self) -> int:
        return self.protocol

    def getTimeStamp(self) -> int:
        return self.timeStamp

    def getHeadBytes(self) -> int:
        return self.headBytes

    def getPayloadBytes(self) -> int:
        return self.payloadBytes

    def getFlags(self) -> int:
        return self.flags

    def getTCPWindow(self) -> int:
        return self.TCPWindow

    def getPayload(self) -> str:
        return self.payload

    def getFwdFlowId(self) -> str:
        return self.fwdFlowId

    def getBwdFlowId(self) -> str:
        return self.bwdFlowId

    def hasFlagFIN(self) -> bool:
        return self.flags & 1

    def hasFlagSYN(self) -> bool:
        return (self.flags >> 1) & 1

    def hasFlagRST(self) -> bool:
        return (self.flags >> 2) & 1

    def hasFlagPSH(self) -> bool:
        return (self.flags >> 3) & 1

    def hasFlagACK(self) -> bool:
        return (self.flags >> 4) & 1

    def hasFlagURG(self) -> bool:
        return (self.flags >> 5) & 1

    def hasFlagECE(self) -> bool:
        return (self.flags >> 6) & 1

    def hasFlagCWR(self) -> bool:
        return (self.flags >> 7) & 1
