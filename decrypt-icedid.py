#Didier Stevens
#2022/09/29
#decrypt IcedID PNG IDATs

import struct
from Crypto.Cipher import ARC4
import string

def CalculateByteStatistics(dPrevalence=None, data=None):
    averageConsecutiveByteDifference = None
    if dPrevalence == None:
        dPrevalence = {iter: 0 for iter in range(0x100)}
        sumDifferences = 0.0
        previous = None
        if len(data) > 1:
            for byte in data:
                dPrevalence[byte] += 1
                if previous != None:
                    sumDifferences += abs(byte - previous)
                previous = byte
            averageConsecutiveByteDifference = sumDifferences /float(len(data)-1)
    sumValues = sum(dPrevalence.values())
    countNullByte = dPrevalence[0]
    countControlBytes = 0
    countWhitespaceBytes = 0
    countUniqueBytes = 0
    for iter in range(1, 0x21):
        if chr(iter) in string.whitespace:
            countWhitespaceBytes += dPrevalence[iter]
        else:
            countControlBytes += dPrevalence[iter]
    countControlBytes += dPrevalence[0x7F]
    countPrintableBytes = 0
    for iter in range(0x21, 0x7F):
        countPrintableBytes += dPrevalence[iter]
    countHighBytes = 0
    for iter in range(0x80, 0x100):
        countHighBytes += dPrevalence[iter]
    countHexadecimalBytes = 0
    countBASE64Bytes = 0
    for iter in range(0x30, 0x3A):
        countHexadecimalBytes += dPrevalence[iter]
        countBASE64Bytes += dPrevalence[iter]
    for iter in range(0x41, 0x47):
        countHexadecimalBytes += dPrevalence[iter]
    for iter in range(0x61, 0x67):
        countHexadecimalBytes += dPrevalence[iter]
    for iter in range(0x41, 0x5B):
        countBASE64Bytes += dPrevalence[iter]
    for iter in range(0x61, 0x7B):
        countBASE64Bytes += dPrevalence[iter]
    countBASE64Bytes += dPrevalence[ord('+')] + dPrevalence[ord('/')] + dPrevalence[ord('=')]
    entropy = 0.0
    for iter in range(0x100):
        if dPrevalence[iter] > 0:
            prevalence = float(dPrevalence[iter]) / float(sumValues)
            entropy += - prevalence * math.log(prevalence, 2)
            countUniqueBytes += 1
    return sumValues, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes, countHexadecimalBytes, countBASE64Bytes, averageConsecutiveByteDifference

def Scan(dataArg):
    for offset in range(16):
        data = dataArg[offset:]
        key = data[:8]
        data = data[8:]
        oRC4 = ARC4.new(key)
        decrypted = oRC4.decrypt(data)
        result = CalculateByteStatistics(data=decrypted)
        if result[1] < 7.5:
            return [offset, decrypted]
    return [None, None]

def Check(data):
    offset, decrypted = Scan(data)
    if offset != None:
        return b'Offset: %d Header: 0x%08x Size decrypted: %d Shellcode entrypoint: 0x%02x Shellcode size: %d Unknown: %d\n' % ((offset, ) + struct.unpack('<IIIII', decrypted[:4*5]))
    return b'Failed to decrypt\n'

def Decrypt(data):
    offset, decrypted = Scan(data)
    if offset != None:
        return decrypted
    return b''
