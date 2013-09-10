import fcntl
import os
import struct
import subprocess

# use as a global variable
device = None

class WriteError(Exception):
    pass

class TapDevice(object):

    # The constants below are derived from <uapi/linux/if_tun.h>

    # TUNSETIFF flags
    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000  # if set, kernel will not provide Packet Information,
                        # then the packets will be "pure";
                        # otherwise 4 extra bytes will be added to the beginning
                        # of the packet
    # ioctl defines
    TUNSETIFF = 0x400454ca
    TUNSETPERSIST = TUNSETIFF + 1
    TUNSETOWNER = TUNSETIFF + 2

    def __init__(self, name='tapdev'):
        self.name = name
        self.tap = open('/dev/net/tun', 'r+b')

        ifr = struct.pack('16sH', name, TapDevice.IFF_TAP | TapDevice.IFF_NO_PI)
        fcntl.ioctl(self.tap, TapDevice.TUNSETIFF, ifr)

    def setIPv4Address(self, ipv4='192.168.1.101', prefixLength):
        command = ['ifconfig', self.name, ipv4 + '/' + str(prefixLength)]
        print 'config IPv4 address:', command
        subprocess.check_call(command)
        self.__turnUpInterface()

    def setIPv6Address(self, ipv6, prefixLength):
        command = ['ip', '-6', 'addr', 'add', ipv6 + '/' + str(prefixLength),
                   'dev', self.name]
        print 'config IPv6 address:', command
        subprocess.check_call(command)
        self.__turnUpInterface()

    def __turnUpInterface(self):
        command = ['ifconfig', self.name, 'up']
        subprocess.check_call(command)

    def read(self, size=2048):
        # note that size is the maximum size to read
        return os.read(self.tap.fileno(), size)

    def write(self, packetBytes):
        bytesWritten = os.write(self.tap.fileno(), packetBytes)
        if bytesWritten == 0:
            raise WriteError
