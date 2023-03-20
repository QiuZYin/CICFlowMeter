from PacketReader import PacketReader
from FlowGenerator import FlowGenerator

"""
    struct.unpack用法
    H--integer 2个字节
    I--integer 4个字节
    符号! 表示以大端模式(Big-Endian)读取字节,
    即 高位字节 排放在 内存的低地址端,低位字节 排放在 内存的高地址端
    不加符号 表示以小端模式(Little-Endian)读取字节,
    即 高位字节 排放在 内存的高地址端,低位字节 排放在 内存的低地址端
    例如内存中由低到高存放了两个字节 0x12 0x34,
    大端模式下其值为 4*1+3*16+2*256+1*4096=4660
    小端模式下其值为 2*1+1*16+4*256+3*4096=13330
"""

file_path = "F:\\2.pcap.TCP_1-226-51-14_80_192-168-10-12_55900.pcap"
flowTimeout = 120000000
activityTimeout = 5000000
packetReader = PacketReader(file_path)
flowGenerator = FlowGenerator(flowTimeout, activityTimeout)

basicPacket = packetReader.nextPacket()
while basicPacket != None:
    flowGenerator.addPacket(basicPacket)
    basicPacket = packetReader.nextPacket()

# flowGenerator.dumpFeature()
flowGenerator.display()
