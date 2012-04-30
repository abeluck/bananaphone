#! /usr/bin/python

"""
A SOCKS4a transport for use by Twisted protocols. This is written to make
it possible for Twisted clients to take advantage of the anonymous circuits
provided by a local Tor daemon.
"""

import struct
from twisted.internet import protocol, error
from twisted.python import log

class Socks4Error(error.ConnectError):
    """SOCKS4 request rejected"""

class Socks4aServerProtocol(protocol.Protocol):
    # not implemented
    pass
class Socks4aServerFactory(protocol.Factory):
    # not implemented
    pass

class Socks4aClientProtocol(protocol.Protocol):
    socksIsConnected = False
    finished = False
    buf = ""

    def connectionMade(self):
        # send request
        self.sendSocks4aCONNECT(self.factory.host, self.factory.port)

    def sendSocks4aCONNECT(self, host, port):
        msg = (struct.pack(">BBHIB",
                           4, 1, # ver, command=CONNECT
                           port, 1, # port, hostname=0.0.0.1, invalid IP
                                    # means "please resolve name"
                           0, # terminate empty USERID field
                           ) + host + "\x00")
        self.transport.write(msg)

    def handleSocks4aResponse(self, response):
        (version, command, dstport, dstip) = struct.unpack(">BBHI", response)
        assert version == 4
        if command == 90:
            pass # granted
        elif command == 91:
            raise Socks4Error("SOCKS4 request rejected or failed")
        elif command == 92:
            raise Socks4Error("SOCKS4 request rejected, no identd")
        elif command == 93:
            raise Socks4Error("SOCKS4 request rejected, identd doesn't match")

    def dataReceived(self, data):
        assert not self.finished
        if not self.socksIsConnected:
            self.buf = self.buf + data
            if len(self.buf) >= 8:
                response = self.buf[:8]
                self.buf = self.buf[8:]
                self.handleSocks4aResponse(response)
                self.socksIsConnected = True
        if self.socksIsConnected:
            # start the real protocol
            peeraddr = "??"
            p = self.factory.upper_factory.buildProtocol(peeraddr)
            # move the transport to the real protocol object
            self.transport.protocol = p # maybe
            # attach the real protocol to the transport
            p.makeConnection(self.transport)
            # send any leftover data
            if self.buf:
                p.dataReceived(self.buf)
            # fix up the connector to point to the new factory, so things
            # like clientConnectionLost go to the right place
            self.transport.connector.factory = self.factory.upper_factory
            
            # we should be disconnected now
            self.finished = True

class Socks4aClientFactory(protocol.Factory):
    protocol = Socks4aClientProtocol

    def __init__(self, host, port, upper_factory):
        self.host = host
        self.port = port
        self.upper_factory = upper_factory

    # pass on a lot of methods to the upper-layer factory

    def doStart(self):
        protocol.Factory.doStart(self)
        self.upper_factory.doStart()

    def doStop(self):
        self.upper_factory.doStop()
        protocol.Factory.doStop(self)

    def startedConnecting(self, connector):
        self.upper_factory.startedConnecting(connector)

    def clientConnectionFailed(self, connector, reason):
        self.upper_factory.clientConnectionFailed(connector, reason)

    def clientConnectionLost(self, connector, reason):
        # this is only called if the connection is lost during the SOCKS
        # setup phase. After that, the message is sent directly to the upper
        # layer Protocol. Before that, pretend that the connection was never
        # established in the first place, since the upper layer factory
        # hasn't seen it yet.
        self.upper_factory.clientConnectionFailed(connection, reason)

def connectSocks4a(sockshost, socksport,
                   host, port, factory, timeout=30, bindAddress=None,
                   reactor=None):
    if reactor is None:
        from twisted.internet import reactor
    c = reactor.connectTCP(sockshost, socksport,
                           Socks4aClientFactory(host, port, factory))
    return c

# utility to patch reactor.connectTCP to have it use a socks4a proxy instead

def install(sockshost, socksport):
    log.msg("replacing reactor.connectTCP with a SOCKSv4a-enabled version")
    from twisted.internet import reactor, tcp
    #def connectTCP(self, host, port, factory, timeout=30, bindAddress=None):
    # bindAddress is meaningless, so don't accept it
    def connectTCP(host, port, factory, timeout=30):
        c = tcp.Connector(sockshost, socksport,
                          Socks4aClientFactory(host, port, factory),
                          timeout, None, reactor)
        c.connect()
        return c
    reactor.connectTCP = connectTCP


# usage:
#  HTTP client conversion:
# reactor.connectTCP(host, port,
#                    HTTPDownloader(url, file))
# becomes
## reactor.connectTCP(sockshost, socksport,
##                    Socks4aClientFactory(host, port,
##                                         HTTPDownloader(url, file)))
# connectSocks4a(sockshost, socksport, host, port, HTTPDownloader(url, file))
#
# and is most interesting (with Tor) when host="261d3b7bf1827055.onion"
#
