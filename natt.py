
import logging
import selectors
import socket
import struct
import uuid

from collections import defaultdict


logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)

# TODO:
# * UDP sends probably need some sort of retry mechanism.


def ip_to_int(ip_address):
    return struct.unpack('<I', socket.inet_aton(ip_address))[0]


def int_to_ip(integer):
    return socket.inet_ntoa(struct.pack('<I', integer))


class Packet:
    DEFINITIONS = {
        # ACK.
        0xFF: '<BQ',
        # Arbitrary string.
        0x11: '<BQ255s',
        # Empty packet for getting peer src IP/Port.
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

    def add_sock(self, sock):
        self.recv_session[sock] = defaultdict(int)
        self.send_session[sock] = defaultdict(int)

    def recv(self, sock, addr, packet_number):
        if self.recv_session[sock][addr] == packet_number:
            self.recv_session[sock][addr] += 1
            ack = PACKET.to_bytes(0xFF)
            # Only need to send this once. If he doesn't get it then
            # he'll send the packet again and we'll end up here again.
            ARBITER.send(sock, ack, addr)
            return True
        return False

    def recv_ack(self, sock, addr, ack_number):
        """We should get this when a peer has recv'd
        and ack'd something we sent out, so increment
        the send session number."""
        if ack_number == self.send_session[sock][addr]:
            self.send_session[sock][addr] += 1
        # TODO break the "send retry" loop

    def send(self, sock, dest_addr, packet_type, *args):
        # TODO need some kinda magical retry loop with a sleep
        #      that breaks once we recv the ack.
        packet = PACKET.to_bytes(
            packet_type,
            self.send_session[sock][dest_addr],
            *args)
        ARBITER.send(sock, packet, dest_addr)


class Arbiter:
    def __init__(self):
        self.sel = selectors.DefaultSelector()
        self.all_queues = {}
        self.all_buffers = {}
        self.packet_callbacks = {}

    def start(self):
        """Indefinitely handle read/write events of all
        added sockets."""
        while True:
            events = self.sel.select()
            for key, mask in events:
                callbacks = key.data
                for event_type, callback in callbacks.items():
                    if mask & event_type:
                        callback(key.fileobj)

    def send(self, sock, data, addr):
        """Use given sock to send given data to given address."""
        self.all_queues[sock][addr].append(data)

    def add_sock(self, sock, packet_cbs):
        """Add socket with callbacks for when the socket reads
        various types of packets."""
        self.all_queues[sock] = defaultdict(list)
        self.all_buffers[sock] = defaultdict(bytes)
        self.packet_callbacks[sock] = packet_cbs
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

        packet_size = PACKET.SIZES[buff[addr][0]]
        if len(buff[addr]) >= packet_size:
            packet = buff[addr][:packet_size]
            buff[addr] = buff[addr][packet_size:]
            args = PACKET.to_tuple(packet[0], packet)
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
