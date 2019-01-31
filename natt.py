
import heapq
import logging
import selectors
import socket
import struct
import time
import uuid

from collections import defaultdict


logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)


def ip_to_int(ip_address):
    return struct.unpack('<I', socket.inet_aton(ip_address))[0]


def int_to_ip(integer):
    return socket.inet_ntoa(struct.pack('<I', integer))


class Packet:
    # All definitions need BQ (B is magic num, Q is sess num)
    DEFINITIONS = {
        # ACK. Here Q is what is being ACK'd
        0xFF: '<BQ',
        # Arbitrary string.
        0x11: '<BQ255s',
        # Empty packet to send to Lobby to join.
        0x22: '<BQ',
        # IP and Port
        0x33: '<BQIH'
    }
    SIZES = {}

    @classmethod
    def size(cls, packet_type):
        if packet_type not in Packet.SIZES:
            defn = Packet.DEFINITIONS[packet_type]
            Packet.SIZES[packet_type] = struct.calcsize(defn)
        return Packet.SIZES[packet_type]

    @classmethod
    def to_bytes(cls, packet_type, *args):
        return struct.pack(Packet.DEFINITIONS[packet_type], packet_type, *args)

    @classmethod
    def to_tuple(cls, packet_type, packet_bytes):
        return struct.unpack(Packet.DEFINITIONS[packet_type], packet_bytes)[1:]


class SessionHandler:
    """Super lazy "TCP" session handler.
    Basically just in-order packets and retrying..."""
    def __init__(self, sock):
        self.sock = sock
        self.recv_buff = defaultdict(bytes)
        self.packet_callbacks = {}
        self.recv_session = {}
        self.send_session = defaultdict(int)
        self.send_queue = []
        self.retry_looping = False
        ARBITER.add_sess(self)

    def add_callbacks(self, cbs):
        """Add callbacks for the current session. If a packet
        comes in with given magic number, its associated callback
        is called.

        cbs is a dict of magic_num=>func."""
        self.packet_callbacks.update(cbs)

    def read_buff(self):
        """Try to read a packet from all recv'd data.
        Call any associated callbacks for those packets."""
        buff = self.recv_buff
        buff_empty = True
        callbacks = self.packet_callbacks
        # Find a single valid packet to handle
        for addr in buff:
            while buff[addr] and buff[addr][0] not in callbacks:
                buff[addr] = buff[addr][1:]
            if not buff[addr]:
                continue

            packet_size = Packet.size(buff[addr][0])
            if len(buff[addr]) >= packet_size:
                packet = buff[addr][:packet_size]
                buff[addr] = buff[addr][packet_size:]
                args = Packet.to_tuple(packet[0], packet)
                packet_number, args = args[0], args[1:]

                if packet[0] == 0xFF:
                    # This was an acknowledgement that they got our packet
                    self.recv_ack(addr, packet_number)
                    buff_empty = False
                    break
                elif self.recv(addr, packet_number):
                    # This was an expected packet. Call associated callback.
                    callbacks[packet[0]](*args, srcaddr=addr)
                    buff_empty = False
                    break

        # call this method again in case there is still more data in buffs
        if not buff_empty:
            ARBITER.add_timer(self.read_buff, 0)

    def recv(self, addr, packet_number):
        """Send an ACK to the sender that we got this packet number.
        Return True if this was the next packet number expected.
        False otherwise."""
        # Only need to send this once. If he doesn't get it then
        # he'll send the packet again and we'll end up here again.
        if addr not in self.recv_session:
            self.recv_session[addr] = packet_number
        if packet_number <= self.recv_session[addr]:
            ack = Packet.to_bytes(0xFF, packet_number)
            ARBITER.send(self.sock, ack, addr)

        # If this was the packet num we expected, increment
        # the next expected packet num.
        if packet_number == self.recv_session[addr]:
            self.recv_session[addr] += 1
            return True
        return False

    def recv_ack(self, addr, ack_number):
        """Call this when a peer has recv'd
        and ack'd something we sent out."""
        # Filter out packets that have already been ACK'd,
        # we don't need to send them anymore.
        self.send_queue = [p
                           for p in self.send_queue
                           if p[1] == ack_number]

    def _send_retry_loop(self):
        """Retry loop for sending out-going data from the queue."""
        self.retry_looping = False
        for dest_addr, snum, packet in self.send_queue:
            ARBITER.send(self.sock, packet, dest_addr)
            self.retry_looping = True

        # If we sent something, try sending it again in 100ms
        if self.retry_looping:
            ARBITER.add_timer(self._send_retry_loop, 0.1)

    def send(self, dest_addr, packet_type, *args):
        """Use given socket to send packet to destination address."""
        self.send_session[dest_addr] += 1
        snum = self.send_session[dest_addr]
        packet = Packet.to_bytes(
            packet_type,
            snum,
            *args)
        self.send_queue.append((dest_addr, snum, packet))

        # If the send/retry loop isn't running, start it
        if not self.retry_looping:
            self._send_retry_loop()


class Arbiter:
    """Basically the UDP and Timer parts of Libuv."""
    def __init__(self):
        self.sel = selectors.DefaultSelector()
        self.all_queues = {}
        self.timer_heap = []
        self.sock_to_sess = {}

    def start(self):
        """Indefinitely handle read/write events of all
        added sockets and timers."""
        while True:
            timeout = None
            if self.timer_heap:
                timeout = self.timer_heap[0][0] - time.time()

            # handle read/write events
            events = self.sel.select(timeout)
            for key, mask in events:
                if mask & selectors.EVENT_READ:
                    self._handle_read(key.fileobj)
                if mask & selectors.EVENT_WRITE:
                    self._handle_write(key.fileobj)

            # check heap for timer events
            now = time.time()
            while self.timer_heap:
                if self.timer_heap[0][0] < now:
                    _, cb = heapq.heappop(self.timer_heap)
                    cb()
                else:
                    break

    def send(self, sock, data, addr):
        """Use given sock to send given data to given address."""
        self.sel.modify(sock, selectors.EVENT_WRITE)
        self.all_queues[sock].append((addr, data))

    def add_timer(self, cb, seconds):
        """Add a callback to be called after given number of seconds."""
        heapq.heappush(self.timer_heap, (seconds + time.time(), cb))

    def add_sess(self, sess):
        """Add session to use Arbiter's event loop
        for recv'ing and sending packets."""
        self.sock_to_sess[sess.sock] = sess
        self.all_queues[sess.sock] = []
        self.sel.register(sess.sock, selectors.EVENT_READ)

    def _handle_write(self, sock):
        """Handles sending outgoing queued data for this socket."""
        queue = self.all_queues[sock]
        if queue:
            addr, data = queue.pop(0)
            sock.sendto(data, addr)
        if not queue:
            self.sel.modify(sock, selectors.EVENT_READ)

    def _handle_read(self, sock):
        """Handles reading data from socket into their session's buffer."""
        sess = self.sock_to_sess[sock]
        buff = sess.recv_buff
        data, addr = sock.recvfrom(65565)
        buff[addr] += data
        self.add_timer(sess.read_buff, 0)


ARBITER = Arbiter()


class Lobby:
    """Represents a single "lobby" in which clients can connect
    to in order to exchange NAT'd IP:Ports with each other."""

    def __init__(self, port):
        self.clients = []

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        self.sess = SessionHandler(sock)
        self.sess.add_callbacks({0x22: self.add_client})

    def add_client(self, srcaddr):
        """Add given client ip:port to list of clients in lobby.
        The IP should be given in integer format."""
        self.clients.append(srcaddr)
        self.broadcast_peers()

    def broadcast_peers(self):
        """Send address:port of clients to all clients."""
        LOG.info("Sending peer addresses to all peers.")
        for client_addr in self.clients:
            for peer_addr in self.clients:
                if client_addr == peer_addr:
                    continue
                ip_int = ip_to_int(peer_addr[0])
                self.sess.send(client_addr, 0x33, ip_int, peer_addr[1])


class Client:
    """Generic client that connects to other peer clients
    via a NATT lobby."""
    def __init__(self, lobby_addr):
        """Create a client to connect to given lobby_addr tuple."""
        self.uuid = uuid.uuid4()
        LOG.info("Starting client {}".format(self.uuid))
        self.lobby_addr = lobby_addr
        self.peers = []

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sess = SessionHandler(sock)
        self.sess.add_callbacks(
            {
                0x33: self.read_peer,
                0x11: self.read_string
            })

        self.join_lobby()

    def join_lobby(self):
        """Join a lobby. Gives lobby your IP:Port so that
        other clients connected to the lobby can talk to you."""
        LOG.info("Attemping to join lobby {}".format(self.lobby_addr))
        self.sess.send(self.lobby_addr, 0x22)

    def read_peer(self, ip, port, **kwargs):
        """As other peers join the lobby we joined, the lobby
        will send us those peers' addresses so we can talk to them."""
        ip = int_to_ip(ip)
        LOG.info("Got ip:port from lobby: {}:{}".format(ip, port))
        self.peers.append((ip, port))
        self.send_hello_to_peers()

    def send_hello_to_peers(self):
        """Send a friendly greeting to our peers."""
        for addr in self.peers:
            self.sess.send(
                addr,
                0x11,
                bytes("Hello neighbor, I'm {}".format(self.uuid), 'utf8'))
            self.sess.send(
                addr,
                0x11,
                bytes("Goodbye neighbor", 'utf8'))

    def read_string(self, string, **kwargs):
        """Read an arbitrary string from a peer."""
        string = string.decode('utf8')
        string = string.rstrip('\x00')
        LOG.info("Got string: {}".format(string))
