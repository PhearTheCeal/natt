
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

    def __init__(self):
        for magic_num, defn in Packet.DEFINITIONS.items():
            Packet.SIZES[magic_num] = struct.calcsize(defn)

    def to_bytes(self, packet_type, *args):
        return struct.pack(Packet.DEFINITIONS[packet_type], packet_type, *args)

    def to_tuple(self, packet_type, packet_bytes):
        return struct.unpack(Packet.DEFINITIONS[packet_type], packet_bytes)[1:]


class SessionsHandler:
    """Super lazy "TCP" session handler.
    Basically just in-order packets and retrying..."""
    def __init__(self):
        self.recv_session = {}
        self.send_session = {}
        self.send_queue = {}
        self._send_retry_loop()

    def add_sock(self, sock):
        """Create a "TCP" session for given socket.
        This must be called before using recv/send with
        that socket."""
        self.recv_session[sock] = defaultdict(int)
        self.send_session[sock] = defaultdict(int)
        self.send_queue[sock] = defaultdict(list)

    def recv(self, sock, addr, packet_number):
        """Send an ACK to the sender that we got this packet number.
        Return True if this was the next packet number expected.
        False otherwise."""
        # Only need to send this once. If he doesn't get it then
        # he'll send the packet again and we'll end up here again.
        if packet_number <= self.recv_session[sock][addr]:
            ack = PACKET.to_bytes(0xFF, packet_number)
            ARBITER.send(sock, ack, addr)

        # If this was the packet num we expected, increment
        # the next expected packet num.
        if packet_number == self.recv_session[sock][addr]:
            self.recv_session[sock][addr] += 1
            return True
        return False

    def recv_ack(self, sock, addr, ack_number):
        """We should get this when a peer has recv'd
        and ack'd something we sent out, so increment
        the send session number."""
        if ack_number == self.send_session[sock][addr]:
            self.send_session[sock][addr] += 1

    def _send_retry_loop(self):
        """Retry loop for sending out-going data from the queue."""
        for sock in self.send_queue:
            for dest_addr in self.send_queue[sock]:
                if not self.send_queue[sock][dest_addr]:
                    # Nothing to send from sock to dest_addr
                    continue

                snum, packet = self.send_queue[sock][dest_addr][0]
                if snum < self.send_session[sock][dest_addr]:
                    # This packet has already been ACK'd
                    self.send_queue[sock][dest_addr].pop(0)
                    continue

                ARBITER.send(sock, packet, dest_addr)
        # Check again in 100ms
        ARBITER.add_timer(self._send_retry_loop, 0.1)

    def send(self, sock, dest_addr, packet_type, *args):
        """Use given socket to send packet to destination address."""
        snum = self.send_session[sock][dest_addr]
        packet = PACKET.to_bytes(
            packet_type,
            snum,
            *args)
        self.send_queue[sock][dest_addr].append((snum, packet))


class Arbiter:
    """Basically libevent."""
    def __init__(self):
        self.sel = selectors.DefaultSelector()
        self.all_queues = {}
        self.all_buffers = {}
        self.packet_callbacks = {}
        self.timer_heap = []

    def start(self):
        """Indefinitely handle read/write events of all
        added sockets."""
        while True:
            timeout = None
            if self.timer_heap:
                timeout = self.timer_heap[0][0] - time.time()

            # handle read/write events
            events = self.sel.select(timeout)
            for key, mask in events:
                callbacks = key.data
                for event_type, callback in callbacks.items():
                    if mask & event_type:
                        callback(key.fileobj)

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
        self.all_queues[sock][addr].append(data)

    def add_timer(self, cb, seconds):
        """Add a callback to be called after given number of seconds."""
        heapq.heappush(self.timer_heap, (seconds + time.time(), cb))

    def add_sock(self, sock, packet_cbs):
        """Add socket with callbacks for when the socket reads
        various types of packets."""
        self.all_queues[sock] = defaultdict(list)
        self.all_buffers[sock] = defaultdict(bytes)
        self.packet_callbacks[sock] = packet_cbs
        packet_cbs[0xFF] = None  # Special ACK callback for sessions
        mask = selectors.EVENT_READ | selectors.EVENT_WRITE
        cbs = {
            selectors.EVENT_READ: self.the_read_cb,
            selectors.EVENT_WRITE: self.the_write_cb
        }
        self.sel.register(sock, mask, cbs)

    def the_write_cb(self, sock):
        """Handles sending outgoing queued data for all sockets."""
        queues = self.all_queues[sock]
        for addr, queue in queues.items():
            if queue:
                to_send = queue.pop(0)
                # LOG.info("Sending {} to {}".format(to_send, addr))
                sock.sendto(to_send, addr)

    def the_read_cb(self, sock):
        """Handles reading packets and sending packet data to callbacks
        for all sockets."""
        buff = self.all_buffers[sock]
        data, addr = sock.recvfrom(65565)
        buff[addr] += data
        callbacks = self.packet_callbacks[sock]
        while buff[addr] and buff[addr][0] not in callbacks:
            buff[addr] = buff[addr][1:]
        if not buff[addr]:
            return

        packet_size = PACKET.SIZES[buff[addr][0]]
        if len(buff[addr]) >= packet_size:
            packet = buff[addr][:packet_size]
            buff[addr] = buff[addr][packet_size:]
            args = PACKET.to_tuple(packet[0], packet)
            packet_number, args = args[0], args[1:]

            if packet[0] == 0xFF:
                # This was an acknowledgement that they got our packet
                SESS.recv_ack(sock, addr, packet_number)
            elif SESS.recv(sock, addr, packet_number):
                # This was an expected packet. Call associated callback.
                callbacks[packet[0]](*args, srcaddr=addr)


ARBITER = Arbiter()
PACKET = Packet()
SESS = SessionsHandler()


class Lobby:
    """Represents a single "lobby" in which clients can connect
    to in order to exchange NAT'd IP:Ports with each other."""

    def __init__(self, port):
        self.clients = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', port))
        SESS.add_sock(self.sock)
        ARBITER.add_sock(self.sock, {0x22: self.add_client})

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
                SESS.send(self.sock, client_addr, 0x33, ip_int, peer_addr[1])


class Client:
    """Generic client that connects to other peer clients
    via a NATT lobby."""
    def __init__(self, lobby_addr):
        """Create a client to connect to given lobby_addr tuple."""
        self.uuid = uuid.uuid4()
        LOG.info("Starting client {}".format(self.uuid))
        self.lobby_addr = lobby_addr
        self.peers = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        SESS.add_sock(self.sock)
        ARBITER.add_sock(
            self.sock,
            {
                0x33: self.read_peer,
                0x11: self.read_string
            })
        self.join_lobby()

    def join_lobby(self):
        """Join a lobby. Gives lobby your IP:Port so that
        other clients connected to the lobby can talk to you."""
        LOG.info("Attemping to join lobby {}".format(self.lobby_addr))
        SESS.send(self.sock, self.lobby_addr, 0x22)

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
            SESS.send(
                self.sock,
                addr,
                0x11,
                bytes("Hello neighbor, I'm {}".format(self.uuid), 'utf8'))

    def read_string(self, string, **kwargs):
        """Read an arbitrary string from a peer."""
        string = string.decode('utf8')
        string = string.rstrip('\x00')
        LOG.info("Got string: {}".format(string))
