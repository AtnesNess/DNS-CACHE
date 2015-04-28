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

    def getType(self, section="queries"):

        types = {
            "1": "A",
            "2": "NS",
            "5": "CNAME",
            "6": "SOA",
            "15": "MX",
            "16": "TXT"
        }
        if section == "queries":
            type = unpack(">H", self._data[12+self._nameLength:12+self._nameLength+2])[0]
            return types[str(type)]

        if section == "answers":
            res = []
            beginings, length = self.getAnsSections()
            for beg in beginings:
                type = unpack(">H", self._data[beg+2:beg+4])[0]
                res.append(types[str(type)])
            return res


    def setTTL(self, ttl):
        if self.getType() != "A":
            return
        if self.getAnsSections() is None:
            return

        beginings, lengthes = self.getAnsSections()
        ansData = ""
        fmt = ">"
        for i in range(len(lengthes)):
            fmt += "HHHIH"
            if lengthes[i] == 14:
                fmt += "H"
            if lengthes[i] == 16:
                fmt += "I"
            ansData += self._data[beginings[i]:beginings[i]+lengthes[i]]
        unpackedData = unpack(fmt, ansData)
        packedData = list(unpackedData)
        tmp = 0
        for _ in range(self._ans):
            tmp += 3
            packedData[tmp] = ttl
            tmp += 3
        packedData = tuple(packedData)
        self._data = self._data[:beginings[0]]+pack(fmt, *packedData)+self._data[beginings[-1]+lengthes[-1]:]

    def getTTL(self):
        if self.getType() != "A":
            return 3600
        beginings, length = self.getAnsSections()
        ansData = self._data[beginings[0]+6:beginings[0]+10]
        fmt = ">I"
        unpackedData = unpack(fmt, ansData)
        return unpackedData[0]

    def setID(self, ID):
        packedID = pack("H", ID)
        self._data = packedID + self._data[2:]

    def getAnsSections(self):
        if self._ans == 0:
            return None
        cur_pos = 12+self._nameLength+4
        beginings = [cur_pos]
        lengthes = []
        while len(beginings) != self._ans:
            dataLength = int(unpack(">H", self._data[beginings[-1]+10:beginings[-1]+12])[0])
            lengthes.append(10+dataLength+2)
            beginings.append(beginings[-1]+lengthes[-1])
        dataLength = int(unpack(">H", self._data[beginings[-1]+10:beginings[-1]+12])[0])
        lengthes.append(10+dataLength+2)

        return beginings, lengthes

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
        self._name = self._data[12:12+name_length]
        self._name = unpack(str(self._nameLength)+"s", self._name)

        return self._name

    def setName(self, name):
        self._name = name
        self._data = self._data[:12]+pack(str(len(name))+"s", name)+self._data[12+self._nameLength:]
        self._nameLength = len(name)

    def deleteCNAMEs(self):
        ans_types = self.getType(section="answers")
        ans_begginings, ans_lengthes = self.getAnsSections()
        for i in range(len(ans_types)):
            self._data = self._data[:ans_begginings[i]] + pack(">H", 49164) + self._data[ans_begginings[i]+2:]
        for i in range(len(ans_types)):
            if ans_types[i] == "CNAME":
                    self._data = self._data[:ans_begginings[i]]+self._data[ans_begginings[i]+ans_lengthes[i]:]
                    self._ans -= 1
                    self._data = self._data[:6] + pack(">H", self._ans) + self._data[8:]


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
        self._listen = 53

        self._forwarders = []

    @property
    def listen(self):
        return self._listen

    @listen.setter
    def listen(self, port):
        self.listen = port

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
                print request.getType()
                name = request.getName()[0]
                if b"\x03www" in request.getName()[0]:
                    request.setName(request.getName()[0][4:])
                packed_data = request.getData()
                key = packed_data[2:]
                if key in self._cache:
                    cache_data = self._cache[key][0]
                    cache_time = self._cache[key][1]
                    cache_ttl = self._cache[key][2]
                    if time.time() - cache_time <= cache_ttl:
                        reply = DNSPacket(cache_data)
                        reply.setID(unpack("H", packed_data[:2])[0])
                        if reply.getName()[0] != name:
                            reply.deleteCNAMEs()

                        reply.setName(name)
                        reply.setTTL(int(cache_ttl) - time.time() + cache_time)


                        print("cached")
                        self._sock.sendto(reply.getData(), addr)
                        continue
                response = None
                for forwarder in self._forwarders:
                    try:
                        forward_sock.sendto(data, (forwarder.getIPString(), self._listen))
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
                response = response_packet.getData()
                self._sock.sendto(response, addr)
                if response_packet.getAnsSections() is None:
                    continue
                self._cache[key] = [response, time.time(), response_packet.getTTL()]

        finally:
            forward_sock.close()
            self._sock.close()


def isIP(adr):
    regExp = re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3}", adr)
    if regExp is not None and regExp.group(0) == adr:
        return True
    return False


def main(args):
    try:
        serv_port = args.port
        server = UnboundServer(serv_port)

        if args.listen:
            server.listen = args.listen

        if args.forwarders:
            server.forwarders = args.forwarders
        else:
            server.forwarders.append(IP("8.8.8.8"))

        server.start()
    except RuntimeError:
        print("YOU CAN'T SET YOUR SELF AS FORWARDER")
        return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unbound-like server")
    parser.add_argument("port", help="dns-server port", type=int)
    parser.add_argument("-f", "--forwarders", metavar="F", nargs="+", help="dns-server address")
    parser.add_argument("-l", "--listen", metavar="P", type=int, help="port to listen on forwarders")
    args = parser.parse_args()
    main(args)