import struct

from BasicPacketInfo import BasicPacketInfo
from utils import IdGenerator


class PacketReader:
    """
    从PCAP文件读取数据包,并生成BasicPacketInfo格式的数据
    """

    def __init__(self, filename):

        openFile = open(filename, "rb")
        self.pcapData = openFile.read()  # PCAP文件中的所有数据
        openFile.close()

        self.pcapLen = len(self.pcapData)  # PCAP文件的长度
        self.pcapPtr = 24  # 当前指针指向PCAP文件中的字节位置

        if self.pcapData[0:4] == b"\xa1\xb2\xc3\xd4":
            self.typeI = "!I"  # 以大端模式转换
            self.typeH = "!H"
        else:
            self.typeI = "I"  # 以小端模式转换
            self.typeH = "H"

        # 原本该PCAP文件是以大端模式存储,但是它不是标准的PCAP格式
        # 因此我用Wireshark将文件重新保存了一下
        # 这就导致该文件Packet Header部分是以小端模式存储
        # 然而Packet Data部分依旧是大端模式存储
        self.typeH = "!H"

        # TCP数据包ID生成器
        self.generator = IdGenerator()

        self.totGen = IdGenerator()

    def nextPacket(self):

        """
        Description: 生成下一个数据包
        Input: None
        Output: BasicPacketInfo
        """

        # 数据包内容
        packetInfo = None

        while self.pcapPtr < self.pcapLen:

            self.totGen.nextId()

            # 捕获数据包的时间戳高位,精确到秒
            timeHigh = self.pcapData[self.pcapPtr : self.pcapPtr + 4]
            timeHigh = struct.unpack(self.typeI, timeHigh)[0]

            # 捕获数据包的时间戳低位,精确到微秒(1s=10^6us)
            timeLow = self.pcapData[self.pcapPtr + 4 : self.pcapPtr + 8]
            timeLow = struct.unpack(self.typeI, timeLow)[0]

            # 时间戳
            timeStamp = 1000000 * timeHigh + timeLow

            # 数据包的长度,用于计算下一个数据包的位置
            caplen = self.pcapData[self.pcapPtr + 8 : self.pcapPtr + 12]
            caplen = struct.unpack(self.typeI, caplen)[0]

            # 指针向后移动16位
            self.pcapPtr += 16

            # 链路层数据帧
            packetData = self.pcapData[self.pcapPtr : self.pcapPtr + caplen]

            # 指针向后移动caplen位
            self.pcapPtr += caplen

            if self.isIpv4TCP(packetData):
                # 获取数据包信息
                packetInfo = self.getIpv4Info(packetData, timeStamp)
                break

        return packetInfo

    def isIpv4TCP(self, packetData):
        # 不是IPv4协议
        if packetData[12:14] != b"\x08\x00":
            return False
        if packetData[23] != 6:
            return False
        return True

    def getIpv4Info(self, packetData, timeStamp):

        """
        Description: 获取IpV4协议下的数据包信息
        Input: 链路层数据帧, 时间戳
        Output: BasicPacketInfo
        """

        # IP数据包长度
        ipLen = struct.unpack(self.typeH, packetData[16:18])[0]
        # IP数据包内容
        packetIp = packetData[14 : 14 + ipLen]
        # IP数据包头长度
        ipHeadLen = (packetIp[0] & 0x0F) << 2
        # 传输层协议(TCP:6 UDP:17)
        protocol = packetIp[9]
        # 源IP地址
        srcIP = ".".join([str(i) for i in packetIp[12:16]])
        # 目的IP地址
        dstIP = ".".join([str(i) for i in packetIp[16:20]])

        # TCP数据包内容
        packetTCP = packetIp[ipHeadLen:]
        # 源端口
        srcPort = struct.unpack(self.typeH, packetTCP[0:2])[0]
        # 目的端口
        dstPort = struct.unpack(self.typeH, packetTCP[2:4])[0]
        # TCP数据包头长度
        tcpHeadLen = (packetTCP[12] & 0xF0) >> 2
        # TCP控制位
        flags = packetTCP[13]
        # 窗口大小
        windowSize = struct.unpack(self.typeH, packetTCP[14:16])[0]
        # 负载
        payload = packetTCP[tcpHeadLen:]
        # 负载长度
        payloadBytes = len(payload)

        packetInfo = BasicPacketInfo(
            generator=self.generator,
            srcIP=srcIP,
            dstIP=dstIP,
            srcPort=srcPort,
            dstPort=dstPort,
            protocol=protocol,
            timeStamp=timeStamp,
            headBytes=tcpHeadLen,
            payloadBytes=payloadBytes,
            flags=flags,
            TCPWindow=windowSize,
            payload=payload,
        )

        return packetInfo
