import fcntl
import os
import struct
import subprocess
import logging
import socket
import netaddr

# use as a singleton
device = None

LOG = logging.getLogger(__name__)

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

        self.mac_addr = self._get_mac_addr()
        LOG.info('The tap interface has MAC address %s', self.mac_addr)

    def _get_mac_addr(self):
        # This method comes from
        # http://code.activestate.com/recipes/439094-get-the-ip-address-associated-with-a-network-inter/
        # Seems only work on Linux
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', self.name[:15]))
        return netaddr.EUI(''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1])

    def setIPv4Address(self, ipv4='192.168.1.101', prefixLength=24):
        command = ['ifconfig', self.name, ipv4 + '/' + str(prefixLength)]
        LOG.info('Configure tap port with IPv4 address: %s', ' '.join(command))
        subprocess.check_call(command)
        self.__turnUpInterface()

    def setIPv6Address(self, ipv6, prefixLength):
        command = ['ip', '-6', 'addr', 'add', ipv6 + '/' + str(prefixLength),
                   'dev', self.name]
        LOG.info('Configure tap port with IPv6 address: %s', ' '.join(command))
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
