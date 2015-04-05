import argparse
import re
from socket import *
from struct import *
import time


class IP():
    def __init__(self, ip):
        if not isIP(ip):
            ip = gethostbyname(ip)
        self._ip = ip

    def getIPString(self):
        return self._ip

    def __str__(self):
        return "IP({})".format(self._ip)


class UnboundServer(object):
    def __init__(self, ip):
        if not isinstance(ip, IP):
            raise AttributeError("ip should be an instance of IP class")
        self._sock = socket(AF_INET, SOCK_DGRAM)
        self._sock.bind((ip.getIPString(), 53))
        self._sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self._cache = {}
        self._ttl = 86400
        self._forwarders = []

    @property
    def ttl(self):
        return self._ttl

    @ttl.setter
    def ttl(self, ttl):
        print("setter")
        self._ttl = ttl

    @property
    def forwarders(self):
        return self._forwarders

    @forwarders.setter
    def forwarders(self, forwarders):
        self._forwarders = []
        for ip in forwarders:
            self._forwarders.append(IP(ip))

    def start(self):
        forward_sock = socket(AF_INET, SOCK_DGRAM)
        forward_sock.settimeout(0.1)
        try:
            while True:
                data, addr = self._sock.recvfrom(1024)
                unpacked_data = unpack("HHHHHH"+str(len(data)-6*2-4)+"s"+"HH", data)
                key = unpacked_data[1:]
                if key in self._cache:
                    cache_data = self._cache[key][0]
                    cache_time = self._cache[key][1]
                    if time.time() - cache_time <= self._ttl:
                        unpacked_cache = unpack("HHHHHH"+str(len(cache_data)-6*2-4)+"s"+"HH", cache_data)
                        self._sock.sendto(pack("HHHHHH"+str(len(cache_data)-6*2-4)+"s"+"HH", unpacked_data[0],
                                               *unpacked_cache[1:]), addr)
                        continue
                response = None
                for forwarder in self._forwarders:
                    try:
                        forward_sock.sendto(data, (forwarder.getIPString(), 53))
                        response = forward_sock.recv(1024)
                        if response is not None:
                            break
                    except timeout:
                        pass

                if response is None:
                    print ("No response...")
                    continue
                self._cache[key] = [response, time.time()]
                self._sock.sendto(response, addr)
        finally:
            forward_sock.close()
            self._sock.close()


def isIP(adr):
    regExp = re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3}", adr)
    if regExp is not None and regExp.group(0) == adr:
        return True
    return False


def main(args):
    serv_addr = IP(args.address)
    server = UnboundServer(serv_addr)
    if args.ttl:
        server.ttl = args.ttl

    if args.forwarders:
        server.forwarders = args.forwarders

    server.start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unbound-like server")
    parser.add_argument("address", help="dns-server address")
    parser.add_argument("-f", "--forwarders", metavar="F", nargs="+", help="dns-server address")
    parser.add_argument("-t", "--ttl", help="set TTL to cache")
    args = parser.parse_args()
    main(args)