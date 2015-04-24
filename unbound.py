import argparse
import re
from socket import *
from struct import *
import time


class DNSPacket():
    def __init__(self, data):
        self._data = data
        self._quest = None
        self._ans = None
        self._auth = None
        self._add = None
        self._name = None
        self._nameLength = None
        self.getNumbers()
        self.getName()

    def getData(self):

        return self._data

    def setTTL(self, ttl):
        if self.getAnsSections() is None:
            return
        beginings, length = self.getAnsSections()
        ansData = self._data[beginings[0]:beginings[-1]+length]
        fmt = ">"+"HHHIHI"*self._ans
        unpackedData = unpack(fmt, ansData)
        packedData = list(unpackedData)
        tmp = 0
        for _ in range(self._ans):
            tmp += 3
            packedData[tmp] = ttl
            tmp += 3

        packedData = tuple(packedData)
        self._data = self._data[:beginings[0]]+pack(fmt, *packedData)+self._data[beginings[-1]+length:]


    def setID(self, ID):
        data = self._data[:2]
        packedID = pack("H", ID)
        self._data = packedID + self._data[2:]


    def getAnsSections(self):
        if self._ans == 0:
            return None
        beginings = [12+self._nameLength+4+16*i for i in range(self._ans)]
        return beginings, 16



    def getNumbers(self):
        self._quest, self._ans, self._auth, self._add = \
                            unpack(">HHHH", self._data[4:12])

        return self._quest, self._ans, self._auth, self._add

    def getName(self):
        name_length = 0
        for i in self._data[12:]:
            name_length += 1
            if i == pack("b", 0):
                break
        self._nameLength = name_length
        self._name = str(name_length)+"s", self._data[12:12+name_length]
        return self._name


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
    def __init__(self, port):
        if not isinstance(port, int):
            raise AttributeError("port should be an instance of INT")
        self._sock = socket(AF_INET, SOCK_DGRAM)
        self._sock.bind(("", port))
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
                data, addr = self._sock.recvfrom(2048)
                request = DNSPacket(data)
                packed_data = request.getData()
                key = packed_data[2:]
                if key in self._cache:
                    cache_data = self._cache[key][0]
                    cache_time = self._cache[key][1]
                    if time.time() - cache_time <= self._ttl:
                        reply = DNSPacket(cache_data)
                        reply.setTTL(self._ttl - time.time() + cache_time)
                        reply.setID(unpack("H", packed_data[0:2])[0])
                        print("cached")
                        self._sock.sendto(reply.getData(), addr)
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
                print("forward")
                response_packet = DNSPacket(response)
                response_packet.setTTL(self._ttl)
                response = response_packet.getData()
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
    serv_port = args.port
    server = UnboundServer(serv_port)
    if args.ttl:
        server.ttl = args.ttl

    if args.forwarders:
        server.forwarders = args.forwarders
    else:
        server.forwarders.append(IP("8.8.8.8"))

    server.start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unbound-like server")
    parser.add_argument("port", help="dns-server port", type=int)
    parser.add_argument("-f", "--forwarders", metavar="F", nargs="+", help="dns-server address")
    parser.add_argument("-t", "--ttl", help="set TTL to cache")
    args = parser.parse_args()
    main(args)