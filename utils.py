import numpy as np


class IdGenerator:
    """为每个数据包生成唯一的ID"""

    def __init__(self):

        self.id = 0

    def nextId(self):

        self.id += 1
        return self.id

    def nowId(self):

        return self.id


class SummaryStatistics:
    def __init__(self):

        self.N = 0
        self.value = []

    def addValue(self, newValue):
        self.N += 1
        self.value.append(newValue)

    def getN(self):
        return self.N

    def getSum(self):
        return np.sum(self.value)

    def getMax(self):
        return np.max(self.value)

    def getMin(self):
        return np.min(self.value)

    def getMean(self):
        return np.mean(self.value)

    def getStd(self):
        return np.std(self.value)


class BulkStatistics:
    def __init__(self):

        # Bulk数量
        self.cnts = 0
        # Bulk数据包数量
        self.pkts = 0
        # Bulk字节数
        self.bytes = 0
        # Bulk数据包缓存数量
        self.pktsCache = 0
        # Bulk缓存字节数
        self.bytesCache = 0
        # Bulk数据包开始时间戳
        self.startTS = 0
        # Bulk数据包最近时间戳
        self.lastTS = 0
        # Bulk持续时间
        self.duration = 0
