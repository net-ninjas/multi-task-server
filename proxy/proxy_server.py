"""
Helpers for testing code related to HTTP Proxy .

It provides a context manager for starting the proxy.

Copyright (c) 2017 Adi Roiban.
License BSD

This code is based on HTTP Proxy Server in Python.
:copyright: (c) 2013 by Abhinav Singh.
:license: BSD, see LICENSE for more details.

It was modified to use threading instead of multiprocessing so that it will
work in Windows.

It was also updated to match the needs for our testing, and remove the code
for generic handling.
"""
from __future__ import absolute_import, print_function, unicode_literals

import sys
import threading
import datetime
import socket
import select
import time


_IS_END_DEVICE_PROXY = True

# True if we are running on Python 3.
PY3 = sys.version_info[0] == 3

if PY3:
    text_type = str
    binary_type = bytes
    from urllib import parse as urlparse
else:
    text_type = unicode
    binary_type = str
    import urlparse


def text_(s, encoding='utf-8', errors='strict'):
    """ If ``s`` is an instance of ``binary_type``, return
    ``s.decode(encoding, errors)``, otherwise return ``s``"""
    if isinstance(s, binary_type):
        return s.decode(encoding, errors)
    return s  # noqa:cover


def bytes_(s, encoding='utf-8', errors='strict'):
    """ If ``s`` is an instance of ``text_type``, return
    ``s.encode(encoding, errors)``, otherwise return ``s``"""
    if isinstance(s, text_type):  # noqa:cover
        return s.encode(encoding, errors)
    return s


CRLF, COLON, SP = b'\r\n', b':', b' '

HTTP_REQUEST_PARSER = 1
HTTP_RESPONSE_PARSER = 2

HTTP_PARSER_STATE_INITIALIZED = 1
HTTP_PARSER_STATE_LINE_RCVD = 2
HTTP_PARSER_STATE_RCVING_HEADERS = 3
HTTP_PARSER_STATE_HEADERS_COMPLETE = 4
HTTP_PARSER_STATE_RCVING_BODY = 5
HTTP_PARSER_STATE_COMPLETE = 6

CHUNK_PARSER_STATE_WAITING_FOR_SIZE = 1
CHUNK_PARSER_STATE_WAITING_FOR_DATA = 2
CHUNK_PARSER_STATE_COMPLETE = 3


class LogMixin(object):
    """
    Shared code for debugging messages.
    """

    def _log(self, message):
        if not self._debug:
            return
        print("%s: %s" % (time.time(), message))


class ChunkParser(object):
    """
    HTTP chunked encoding response parser.
    """

    def __init__(self):
        self.state = CHUNK_PARSER_STATE_WAITING_FOR_SIZE
        self.body = b''
        self.chunk = b''
        self.size = None

    def parse(self, data):
        more = True if len(data) > 0 else False
        while more:
            more, data = self.process(data)

    def process(self, data):
        if self.state == CHUNK_PARSER_STATE_WAITING_FOR_SIZE:
            line, data = HttpParser.split(data)
            self.size = int(line, 16)
            self.state = CHUNK_PARSER_STATE_WAITING_FOR_DATA
        elif self.state == CHUNK_PARSER_STATE_WAITING_FOR_DATA:
            remaining = self.size - len(self.chunk)
            self.chunk += data[:remaining]
            data = data[remaining:]
            if len(self.chunk) == self.size:
                data = data[len(CRLF):]
                self.body += self.chunk
                if self.size == 0:
                    self.state = CHUNK_PARSER_STATE_COMPLETE
                else:
                    self.state = CHUNK_PARSER_STATE_WAITING_FOR_SIZE
                self.chunk = b''
                self.size = None
        return len(data) > 0, data


class HttpParser(object):
    """
    HTTP request/response parser.
    """

    def __init__(self, type=None):
        self.state = HTTP_PARSER_STATE_INITIALIZED
        self.type = type if type else HTTP_REQUEST_PARSER

        self.raw = b''
        self.buffer = b''

        self.headers = dict()
        self.body = None

        self.method = None
        self.url = None
        self.code = None
        self.reason = None
        self.version = None

        self.chunker = None

    def parse(self, data):
        self.raw += data
        data = self.buffer + data
        self.buffer = b''

        more = True if len(data) > 0 else False
        while more:
            more, data = self.process(data)
        self.buffer = data

    def process(self, data):
        if (
            self.state >= HTTP_PARSER_STATE_HEADERS_COMPLETE and
            (self.method == b"POST" or self.type == HTTP_RESPONSE_PARSER)
                ):
            if not self.body:
                self.body = b''

            if b'content-length' in self.headers:
                self.state = HTTP_PARSER_STATE_RCVING_BODY
                self.body += data
                if len(self.body) >= int(self.headers[b'content-length'][1]):
                    self.state = HTTP_PARSER_STATE_COMPLETE
            elif (
                b'transfer-encoding' in self.headers and
                self.headers[b'transfer-encoding'][1].lower() == b'chunked'
                    ):
                if not self.chunker:
                    self.chunker = ChunkParser()
                self.chunker.parse(data)
                if self.chunker.state == CHUNK_PARSER_STATE_COMPLETE:
                    self.body = self.chunker.body
                    self.state = HTTP_PARSER_STATE_COMPLETE

            return False, b''

        line, data = HttpParser.split(data)

        if line is False:
            return line, data

        if self.state < HTTP_PARSER_STATE_LINE_RCVD:
            self.process_line(line)
        elif self.state < HTTP_PARSER_STATE_HEADERS_COMPLETE:
            self.process_header(line)

        if (
            self.state == HTTP_PARSER_STATE_HEADERS_COMPLETE and
            self.type == HTTP_REQUEST_PARSER and
            not self.method == b"POST" and
            self.raw.endswith(CRLF * 2)
                ):
            self.state = HTTP_PARSER_STATE_COMPLETE

        return len(data) > 0, data

    def process_line(self, data):
        line = data.split(SP)
        if self.type == HTTP_REQUEST_PARSER:
            self.method = line[0].upper()
            self.url = urlparse.urlsplit(line[1])
            self.version = line[2]
        else:
            self.version = line[0]
            self.code = line[1]
            self.reason = b' '.join(line[2:])
        self.state = HTTP_PARSER_STATE_LINE_RCVD

    def process_header(self, data):
        if len(data) == 0:
            if self.state == HTTP_PARSER_STATE_RCVING_HEADERS:
                self.state = HTTP_PARSER_STATE_HEADERS_COMPLETE
            elif self.state == HTTP_PARSER_STATE_LINE_RCVD:
                self.state = HTTP_PARSER_STATE_RCVING_HEADERS
        else:
            self.state = HTTP_PARSER_STATE_RCVING_HEADERS
            parts = data.split(COLON)
            key = parts[0].strip()
            value = COLON.join(parts[1:]).strip()
            self.headers[key.lower()] = (key, value)

    def build_url(self):
        if not self.url:
            return b'/None'

        url = self.url.path
        if url == b'':
            url = b'/'
        if not self.url.query == b'':
            url += b'?' + self.url.query
        if not self.url.fragment == b'':
            url += b'#' + self.url.fragment
        return url

    def build_header(self, k, v):
        return k + b": " + v + CRLF

    def build(self, del_headers=None, add_headers=None):
        req = b" ".join([self.method, self.build_url(), self.version])
        req += CRLF

        if not del_headers:
            del_headers = []
        for k in self.headers:
            if k not in del_headers:
                req += self.build_header(
                    self.headers[k][0], self.headers[k][1])

        if not add_headers:
            add_headers = []
        for k in add_headers:
            req += self.build_header(k[0], k[1])

        req += CRLF
        if self.body:
            req += self.body

        return req

    @staticmethod
    def split(data):
        pos = data.find(CRLF)
        if pos == -1:
            return False, data
        line = data[:pos]
        data = data[pos + len(CRLF):]
        return line, data


class Connection(LogMixin):
    """
    TCP server/client connection abstraction.
    """

    def __init__(self, what, debug):
        self.buffer = b''
        self.closed = False
        self.what = what  # server or client
        self._debug = debug

    def send(self, data):
        return self.conn.send(data)

    def recv(self, bytes=8192):
        try:
            data = self.conn.recv(bytes)
            if len(data) == 0:
                self._log('recvd 0 bytes from %s' % self.what)
                return None
            self._log('rcvd %d bytes from %s' % (len(data), self.what))
            return data
        except Exception as e:
            self._log(
                'Exception while receiving from connection %s %r '
                'with reason %r' % (self.what, self.conn, e)
                )
            return None

    def close(self):
        self.conn.close()
        self.closed = True

    def buffer_size(self):
        return len(self.buffer)

    def has_buffer(self):
        return self.buffer_size() > 0

    def queue(self, data):
        self.buffer += data

    def flush(self):
        pre_buffer = self.buffer
        sent = self.send(self.buffer)
        self.buffer = self.buffer[sent:]
        self._log('flushed %d bytes to %s, buffer=%s' % (sent, self.what, pre_buffer))

    def get_buffer(self):
        return self.buffer


class ProxyServerConnection(Connection):
    """Establish connection to destination server."""

    def __init__(self, host, port, debug):
        super(ProxyServerConnection, self).__init__(b'server', debug)
        self.addr = (host, int(port))

    def connect(self):
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((self.addr[0], self.addr[1]))


class ProxyClientConnection(Connection):
    """Accepted client connection."""

    def __init__(self, conn, addr, debug):
        super(ProxyClientConnection, self).__init__(b'client', debug)
        self.conn = conn
        self.addr = addr


class ProxyError(Exception):
    pass


class ProxyConnectionFailed(ProxyError):

    def __init__(self, host, port, reason):
        self.host = host
        self.port = port
        self.reason = reason

    def __str__(self):
        return '<ProxyConnectionFailed - %s:%s - %s>' % (
            self.host, self.port, self.reason)


class ProxyConnection(LogMixin):
    """
    HTTP proxy implementation.

    Accepts connection object and act as a proxy between client and server.

    Code from proxy_py which removed the multiprocessing usage as it does not
    work on Windows.
    """

    def __init__(self, client, debug):
        super(ProxyConnection, self).__init__()
        self.start_time = self._now()
        self.last_activity = self.start_time
        self.client = client
        self.server = None
        self.request = HttpParser()
        self.response = HttpParser(HTTP_RESPONSE_PARSER)
        self.connection_established_pkt = CRLF.join([
            b'HTTP/1.1 200 Connection established',
            b'Proxy-agent: proxy.py',
            CRLF,
            ])
        self._debug = debug

    def _now(self):
        return datetime.datetime.utcnow()

    def _inactive_for(self):
        return (self._now() - self.last_activity).seconds

    def _is_inactive(self):
        return self._inactive_for() > 30

    def _process_request(self, data):
        # once we have connection to the server
        # we don't parse the http request packets
        # any further, instead just pipe incoming
        # data from client to server
        if self.server and not self.server.closed:
            self.server.queue(data)
            return

        # parse http request
        self.request.parse(data)

        # once http request parser has reached the state complete
        # we attempt to establish connection to destination server
        if self.request.state == HTTP_PARSER_STATE_COMPLETE:
            self._log('request parser is in state complete')
            self.proxy_request()

    def proxy_request(self):

        if self.request.method == b"CONNECT":
            host, port = self.request.url.path.split(COLON)
        elif self.request.url:
            if self.request.url.port:
                port = self.request.url.port
            else:
                port = 80
            host = self.request.url.hostname

        self.server = ProxyServerConnection(host, port, self._debug)
        try:
            self._log('connecting to server %s:%s' % (host, port))
            self.server.connect()
            self._log('connected to server %s:%s' % (host, port))
        except Exception as e:
            self.server.closed = True
            raise ProxyConnectionFailed(host, port, repr(e))

        # for http connect methods (https requests)
        # queue appropriate response for client
        # notifying about established connection
        if self.request.method == b"CONNECT":
            self.client.queue(self.connection_established_pkt)
        # for usual http requests, re-build request packet
        # and queue for the server with appropriate headers
        else:
            self.server.queue(self.request.build(
                del_headers=[
                    b'proxy-connection', b'connection', b'keep-alive'],
                add_headers=[(b'Connection', b'Close')]
            ))

    def _process_response(self, data):
        # parse incoming response packet
        # only for non-https requests
        if not self.request.method == b"CONNECT":
            self.response.parse(data)

        # queue data for client
        self.client.queue(data)

    def _access_log(self):
        host, port = self.server.addr if self.server else (None, None)
        if self.request.method == b"CONNECT":
            self._log(
                "%s:%s - %s %s:%s" % (
                    self.client.addr[0],
                    self.client.addr[1],
                    self.request.method, host, port,
                    ))
        elif self.request.method:
            self._log(
                "%s:%s - %s %s:%s%s - %s %s - %s bytes" % (
                    self.client.addr[0],
                    self.client.addr[1],
                    self.request.method,
                    host,
                    port,
                    self.request.build_url(),
                    self.response.code,
                    self.response.reason,
                    len(self.response.raw),
                    ))

    def _get_waitable_lists(self):
        rlist, wlist, xlist = [self.client.conn], [], []
        self._log('*** watching client for read ready')

        if self.client.has_buffer():
            self._log(
                'pending client buffer found, watching client for write ready')
            wlist.append(self.client.conn)

        if self.server and not self.server.closed:
            self._log(
                'connection to server exists, watching server for read ready')
            rlist.append(self.server.conn)

        if self.server and not self.server.closed and self.server.has_buffer():
            self._log(
                'connection to server exists and pending server buffer found, '
                'watching server for write ready'
                )
            wlist.append(self.server.conn)

        return rlist, wlist, xlist

    def _process_wlist(self, w):
        if self.client.conn in w:
            self._log('client is ready for writes, flushing client buffer')
            self.client.flush()

        if self.server and not self.server.closed and self.server.conn in w:
            self._log('server is ready for writes, flushing server buffer')
            self.server.flush()

    def _process_rlist(self, r):
        if self.client.conn in r:
            self._log('client is ready for reads, reading')
            data = self.client.recv()
            self.last_activity = self._now()

            if not data:
                self._log('client closed connection, breaking')
                return True

            try:
                self._process_request(data)
            except ProxyConnectionFailed as e:
                self._log(e)
                self.client.queue(CRLF.join([
                    b'HTTP/1.1 502 Bad Gateway',
                    b'Proxy-agent: proxy.py',
                    b'Content-Length: 11',
                    b'Connection: close',
                    CRLF
                    ]) + b'Bad Gateway')
                self.client.flush()
                return True

        if self.server and not self.server.closed and self.server.conn in r:
            self._log('server is ready for reads, reading')
            data = self.server.recv()
            self.last_activity = self._now()

            if not data:
                self._log('server closed connection')
                self.server.close()
            else:
                self._process_response(data)

        return False

    def _process(self):
        while True:
            rlist, wlist, xlist = self._get_waitable_lists()
            r, w, x = select.select(rlist, wlist, xlist, 1)

            self._process_wlist(w)
            if self._process_rlist(r):
                break

            if self.client.buffer_size() == 0:
                if self.response.state == HTTP_PARSER_STATE_COMPLETE:
                    self._log(
                        'client buffer is empty and response state is '
                        'complete, breaking')
                    break

                if self._is_inactive():
                    self._log(
                        'client buffer is empty and maximum '
                        'inactivity has reached, breaking'
                        )
                    break

    def start(self):
        self._log('Proxying connection %r at address %r' % (
            self.client.conn, self.client.addr))
        try:
            self._process()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            self._log(
                'Exception while handling connection %r with reason %r' % (
                    self.client.conn, e))
        finally:
            self._log(
                "closing client connection with pending client "
                "buffer size %d bytes" % self.client.buffer_size()
                )
            self.client.close()
            if self.server:
                self._log(
                    "closed client connection with pending server buffer "
                    "size %d bytes" % self.server.buffer_size()
                    )
            self._access_log()
            self._log(
                'Closing proxy for connection %r at '
                'address %r' % (self.client.conn, self.client.addr))


class ProxyToEndDeviceConnection(ProxyConnection):

    def proxy_request(self):
        if self.client:
            #self.client.queue(self.server.buffer)
            request = self.request.build(
                del_headers=[
                    b'proxy-connection', b'connection', b'keep-alive'],
                add_headers=[(b'Connection', b'Close')])

            # TODO: RAMI -
            # 1. translate to protobuf
            # 2. get active end-device connection
            # 3. send it to end-device
            # 4. get response, and queue to client...
            print("server=%s, url=%s, method=%s" % (request, self.request.url.path, self.request.method))
            
            #super(ProxyToEndDeviceConnection, self).proxy_request()
        return;


        if self.request.method == b"CONNECT":
            host, port = self.request.url.path.split(COLON)
        elif self.request.url:
            if self.request.url.port:
                port = self.request.url.port
            else:
                port = 80
            host = self.request.url.hostname

        self.server = ProxyServerConnection(host, port, self._debug)
        try:
            self._log('connecting to server %s:%s' % (host, port))
            self.server.connect()
            self._log('connected to server %s:%s' % (host, port))
        except Exception as e:
            self.server.closed = True
            raise ProxyConnectionFailed(host, port, repr(e))

        # for http connect methods (https requests)
        # queue appropriate response for client
        # notifying about established connection
        if self.request.method == b"CONNECT":
            self.client.queue(self.connection_established_pkt)
        # for usual http requests, re-build request packet
        # and queue for the server with appropriate headers
        else:

            #print("data===" + builded)
            self.server.queue(self.request.build(
                del_headers=[
                    b'proxy-connection', b'connection', b'keep-alive'],
                add_headers=[(b'Connection', b'Close')]))


class SingleThreadedHTTPProxy(threading.Thread, LogMixin):
    """
    HTTP Proxy that runs in a single thread.
    """
    TIMEOUT = 1




    def __init__(
        self, cond, ip='127.0.0.1', port=0, reject_reason=None, debug=False, is_end_device_proxy=_IS_END_DEVICE_PROXY
            ):
        threading.Thread.__init__(self)
        self.ready = False
        self.cond = cond
        self._ip = ip
        self._port = port
        self._debug = debug
        self._reject_reason = reject_reason
        self.active_connection = None
        self.running = False
        self._connections = []

        # Class use to handle a connection.
        if is_end_device_proxy:
            self._connection_class = ProxyToEndDeviceConnection
        else:
            self._connection_class = ProxyConnection

    @property
    def server_address(self):
        return self.socket.getsockname()

    def run(self):
        self.cond.acquire()
        self.running = True

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self._ip, self._port))
        self.socket.listen(100)

        address = self.server_address
        self._log('Proxy start on port %s %d' % (address[0], address[1]))

        self.ready = True
        if self.cond:
            self.cond.notifyAll()
            self.cond.release()
        # Start the actual HTTP server.
        self._acceptConnections()

    def _acceptConnections(self):
        try:
            while True:
                if not self.running:
                    break

                conn, addr = self.socket.accept()

                if not self.running:
                    # We got a new connection, but the server is already
                    # stopped.
                    break

                client = ProxyClientConnection(conn, addr, self._debug)
                self.active_connection = conn
                self._handle(client)
                self.active_connection = None
        except Exception as e:
            self._log('Proxy error %r' % e)
        finally:
            self.socket.close()
            self._log('Closing proxy')

    def _handle(self, client):
        if self._reject_reason:
            client.send('HTTP/1.1 501 %s\r\n' % (self._reject_reason,))
            return

        proc = self._connection_class(client, debug=self._debug)
        self._connections.append(proc)
        self._log('Handle connection %r' % (client.conn.getsockname(),))
        proc.start()


class HTTPProxyContext(object):
    """
    A context which executes a threaded HTTP proxy.
    """

    def __init__(
            self, ip='127.0.0.1', port=0, reject_reason=None, debug=False):
        self.cond = threading.Condition()
        self.server = SingleThreadedHTTPProxy(
            cond=self.cond,
            ip=ip,
            port=port,
            reject_reason=reject_reason,
            debug=debug,
            )

    def __enter__(self):
        self.cond.acquire()
        self.server.start()

        # Wait until the server is ready.
        while not self.server.ready:
            self.cond.wait()
        self.cond.release()

        #from chevah.server.testing.testcase import ServerTestCase
        # Even if the thread ready, it might still need some time
        # to be ready.
        #if ServerTestCase.os_version == 'hpux':  # noqa:cover
        #    time.sleep(0.1)
        #else:
        #    time.sleep(0.02)

        return self

    def __exit__(self, exc_type, exc_value, tb):
        self._stopServer()
        self.server.join(1)

        if self.server.isAlive():
            # Even if the thread has joined, it might still need some time
            # to close.
            time.sleep(0.01)
            if self.server.isAlive():
                raise AssertionError('Server still running')
        return False

    @property
    def port(self):
        return self.server.server_address[1]

    @property
    def ip(self):
        return self.server.server_address[0]

    @property
    def connections(self):
        """
        List of connections made to this proxy.
        """
        return self.server._connections

    def _stopServer(self):
        self.server._reject_reason = None
        self.server.running = False
        connection = self.server.active_connection

        try:
            if connection:
                # We already have an active ongoing connection
                # so we can just stop it.
                connection.shutdown(socket.SHUT_RDWR)
                connection.close()
            else:
                # Stop waiting for data from new connection.
                # This is done triggering a new connection to unblock the
                # accept() call.
                close_connection = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM)
                close_connection.connect((self.ip, self.port))
                close_connection.close()
        except Exception:
            # Maybe the server is already down,
            pass


if __name__ == "__main__":
    with  HTTPProxyContext(ip='127.0.0.1', port=8080, reject_reason=None, debug=True):
        print("running...")
        while 1:
            time.sleep(1)

    print("done")


