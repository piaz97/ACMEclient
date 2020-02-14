from dnslib.server import BaseResolver, DNSServer, DNSLogger
from dnslib import A, TXT, RR, QTYPE, AAAA

from os.path import join, dirname, realpath, isfile


class MyResolver(BaseResolver):
    # qr = 1 => reply (0 would have been query)
    # aa = 1 => authoritative answer
    # ra = 1 => recursion available, supported
    address = None

    def __init__(self, address, *args, **kwargs):
        super(MyResolver, self).__init__(*args, **kwargs)
        self.address = str(address)

    def resolve(self, request, handler):
        if self.address is None:
            raise Exception("address not set")

        reply = request.reply()
        q_name = request.q.qname
        q_rtype = request.q.qtype

        if q_rtype == QTYPE.A:
            reply.add_answer(RR(rname=q_name,  rtype=q_rtype, rdata=A(str(self.address)), ttl=10))

        elif q_rtype == QTYPE.TXT:
            path = join(dirname(realpath(__file__)), "challenge_tokens/"+str(q_name))[:-1]

            wild_path = join(dirname(realpath(__file__)), "challenge_tokens/wildcard"+str(q_name))[:-1]

            with open(path, "r") as file:
                token = file.read()
            reply.add_answer(RR(rname=q_name, rtype=q_rtype, rdata=TXT(token), ttl=10))

            if isfile(wild_path):
                print("it is a wildcard")
                with open(wild_path, "r") as file:
                    token = file.read()
                reply.add_answer(RR(rname=q_name, rtype=q_rtype, rdata=TXT(token), ttl=10))
            else:
                print("it is not a wildcard")

        return reply


class MyDNSServer:

    server = None

    @classmethod
    def start(self, address):

        my_resolver = MyResolver(address)

        logger = DNSLogger(prefix=False)

        self.server = DNSServer(my_resolver, port=10053, address=str(address), logger=logger)

        self.server.start_thread()
        print("DNS server is UP")
        # while server.isAlive():
        #   time.sleep(1)

    @classmethod
    def shut_down(self):
        print("shutting down the DNS server..\n")
        self.server.stop()


