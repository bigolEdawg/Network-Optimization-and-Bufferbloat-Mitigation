import socket
import threading
import random
import struct
import sys

# ////////////////////////////// SERVER DATA //////////////////////////////
HOST = "localhost" if len(sys.argv) < 2 else sys.argv[1]
PORT = 12235
# /////////////////////////////////////////////////////////////////////////

# ////////////////////////////// PACKET DATA //////////////////////////////
MIN_PORT = 1024
MAX_PORT = 65535
RECV_LEN = 1024
HEADER_SIZE = 12
PADDING = 4
STEP = 2
STEP_CLIENT = 1
PSECRET = 0
MESSAGE_A = "hello world\0"
# /////////////////////////////////////////////////////////////////////////

# ////////////////////////////// FORMAT DATA //////////////////////////////
# expected format for packets
F_HEADER = "!2I2H"                               # header format
F_RECV_A = "!" + str(len(MESSAGE_A)) + "s"       # stage a recv payload
F_RESPONSE_A = "!4I"                             # stage a send payload
F_RECV_B = "!I"                                  # stage b recv payload
F_PACKED_B = "!c"                               # stage b payload filler
F_ACK_B = "!I"                                   # stage b acknowledgement
F_RESPONSE_B = "!2I"                             # stage b send payload
F_RESPONSE_C = "!3Ic"                            # stage c send payload
F_RECV_D = "!c"                                  # stage d recv payload
F_RESPONSE_D = "!I"                              # stage d send payload
# /////////////////////////////////////////////////////////////////////////


# ////////////////////////////// SERVER ClASS //////////////////////////////

class Server:

    def __init__(self, host, port):
        # initialize server attributes
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_ports = set()
        self.tcp_ports = set()

        # initialize lock attributes for threads
        self.udp_ports_lock = threading.Lock()
        self.tcp_ports_lock = threading.Lock()
        self.socket_lock = threading.Lock()

    def __call__(self):
        # run server
        # loop to accept clients
        # create thread for new client
        self.socket.bind((self.host, self.port))
        while True:
            message, address = self.socket.recvfrom(RECV_LEN)
            threading.Thread(target=self.__handle_client, args=(message, address)).start()

    def __del__(self):
        self.socket.close()

    def __handle_client(self, message, address):
        handler = ClientHandler()
        exception = False
        udp_port = None
        tcp_port = None
        udp_address = None
        s_udp = None
        s_tcp = None

        # stage a
        try:
            if not handler.validate_a(message, PSECRET):
                return

            # find random port that is not in use for part b
            # mark port as in use
            udp_port = random.randint(MIN_PORT, MAX_PORT)
            with self.udp_ports_lock:
                while udp_port in self.udp_ports:
                    udp_port = random.randint(MIN_PORT, MAX_PORT)
                self.udp_ports.add(udp_port)

            s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s_udp.bind((self.host, udp_port))

            # send response
            packet = handler.get_response_a(udp_port)
            with self.socket_lock:
                self.socket.sendto(packet, address)

        except socket.error:
            exception = True
            return
        except struct.error:
            exception = True
            return
        finally:
            # release resources if we caught an exception
            if exception and udp_port is not None:
                with self.udp_ports_lock:
                    self.udp_ports.discard(udp_port)
            if exception and udp_port is not None:
                s_udp.close()

        # stage b
        try:
            i = 0

            # read packets, randomly deciding if packets should be dropped or acknowledged
            # loop until handler.num packets have been accepted
            while i < handler.num:
                s_udp.settimeout(3)
                data, udp_address = s_udp.recvfrom(RECV_LEN)
                if udp_address[0] != address[0]:
                    continue
                if random.randint(0, 1) == 0:
                    continue
                if not handler.validate_b(data, i):
                    return
                ack = handler.get_ack_b(i)
                s_udp.sendto(ack, udp_address)
                i += 1

            # find random port that is not in use for part c/d
            # mark port as in use

            tcp_port = random.randint(MIN_PORT, MAX_PORT)
            with self.tcp_ports_lock:
                while tcp_port in self.tcp_ports:
                    tcp_port = random.randint(MIN_PORT, MAX_PORT)
                self.tcp_ports.add(tcp_port)

            s_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_tcp.bind((self.host, tcp_port))
            s_tcp.listen()

            # send response
            packet = handler.get_response_b(tcp_port)
            s_udp.sendto(packet, udp_address)

        except socket.error:
            exception = True
            return
        except struct.error:
            exception = True
            return
        finally:
            # handle resources properly
            s_udp.close()
            with self.udp_ports_lock:
                self.udp_ports.discard(udp_port)
            if exception and tcp_port is not None:
                with self.tcp_ports_lock:
                    self.tcp_ports.discard(tcp_port)
            if exception and s_tcp is not None:
                s_tcp.close()

        # stage c/d
        recv_len = handler.calc_size(handler.len2)
        try:
            s_tcp.settimeout(3)

            # accept the correct client
            tcp_s, tcp_address = s_tcp.accept()
            while tcp_address[0] != address[0]:
                s_tcp.settimeout(3)
                tcp_s, tcp_address = s_tcp.accept()

            try:
                # stage c
                packet = handler.get_response_c()
                tcp_s.sendall(packet)

                # stage d
                # read handler.num2 packets
                # validate payload is length=handler.len2 and stuffed with c
                for i in range(handler.num2):
                    tcp_s.settimeout(3)
                    data = tcp_s.recv(recv_len)
                    if not handler.validate_d(data):
                        return
                # send response
                packet = handler.get_response_d()
                tcp_s.sendall(packet)
            finally:
                # handle client socket
                tcp_s.close()

        except socket.error:
            return
        except struct.error:
            return
        finally:
            # hand listening socket
            with self.tcp_ports_lock:
                self.tcp_ports.discard(tcp_port)
            s_tcp.close()

# //////////////////////////// END SERVER ClASS ////////////////////////////


# /////////////////////////// CLIENTHANDLER ClASS //////////////////////////
class ClientHandler:

    def __init__(self):
        self.num = random.randint(1, 30)
        self.num2 = random.randint(1, 30)
        self.len = random.randint(1, 100)
        self.len2 = random.randint(1, 100)
        self.secret_a = random.randint(1, 500)
        self.secret_b = random.randint(1, 500)
        self.secret_c = random.randint(1, 500)
        self.secret_d = random.randint(1, 500)
        self.c = chr(random.randint(0, 127)).encode('ascii')
        self.sid = 0

    # return true is stage a packet is valid
    # else return false
    def validate_a(self, data, init_secret):
        # check packet size
        payload_len = struct.calcsize(F_RECV_A)
        expected_bytes = self.calc_size(payload_len)
        if len(data) != expected_bytes:
            return False

        # check payload length and psecret
        payload_len_recv, psecret, step, self.sid = struct.unpack_from(F_HEADER, data, 0)
        if payload_len_recv != payload_len or psecret != init_secret or step != STEP_CLIENT:
            return False

        # check payload message
        message, = struct.unpack_from(F_RECV_A, data, HEADER_SIZE)
        message = message.decode('utf-8')
        if message != MESSAGE_A:
            return False

        return True

    # payload = [num, len, port, secret_a]
    def get_response_a(self, port):
        packet = self.get_buffer_with_header(struct.calcsize(F_RESPONSE_A), self.secret_b, self.sid)
        struct.pack_into(F_RESPONSE_A, packet, HEADER_SIZE, self.num, self.len, port, self.secret_a)
        return packet

    # return true if stage_b packet is valid
    # else return false
    def validate_b(self, data, i):
        # check packet size
        payload_len = struct.calcsize(F_RECV_B) + self.len
        expected_bytes = self.calc_size(payload_len)
        if len(data) != expected_bytes:
            return False

        # check payload length and psecret
        payload_len_recv, psecret, step, self.sid = struct.unpack_from(F_HEADER, data, 0)
        if payload_len_recv != payload_len or psecret != self.secret_a or step != STEP_CLIENT:
            return False

        # check packet_id
        packet_id, = struct.unpack_from(F_RECV_B, data, HEADER_SIZE)
        if packet_id != i:
            return False

        # check packet is stuffed with 0s
        for j in range(self.len):
            char, = struct.unpack_from(F_PACKED_B, data, HEADER_SIZE + struct.calcsize(F_RECV_B) + j)
            if char != b'\0':
                return False

        return True

    # payload = [i]
    def get_ack_b(self, i):
        ack = self.get_buffer_with_header(struct.calcsize(F_ACK_B), self.secret_a, self.sid)
        struct.pack_into(F_ACK_B, ack, HEADER_SIZE, i)
        return ack

    # payload = [port, secret_b]
    def get_response_b(self, port):
        packet = self.get_buffer_with_header(struct.calcsize(F_RESPONSE_B), self.secret_a, self.sid)
        struct.pack_into(F_RESPONSE_B, packet, HEADER_SIZE, port, self.secret_b)
        return packet

    # payload = [num2, len2, secret_c, c]
    def get_response_c(self):
        packet = self.get_buffer_with_header(struct.calcsize(F_RESPONSE_C), self.secret_b, self.sid)
        struct.pack_into(F_RESPONSE_C, packet, HEADER_SIZE, self.num2, self.len2, self.secret_c, self.c)
        return packet

    # return true if stage d packet is valid
    # else return false
    def validate_d(self, data):
        # check packet size
        payload_len = self.len2 * struct.calcsize(F_RECV_D)
        expected_bytes = self.calc_size(payload_len)
        if len(data) != expected_bytes:
            return False

        # check payload length and psecret
        payload_len_recv, psecret, step, self.sid = struct.unpack_from(F_HEADER, data, 0)
        if payload_len_recv != payload_len or psecret != self.secret_c or step != STEP_CLIENT:
            return False

        # check payload if stuffed with c
        for j in range(payload_len):
            c_recv, = struct.unpack_from(F_RECV_D, data, HEADER_SIZE + j)
            if c_recv != self.c:
                return False

        return True

    # payload = [secret_d]
    def get_response_d(self):
        packet = self.get_buffer_with_header(struct.calcsize(F_RESPONSE_D), self.secret_c, self.sid)
        struct.pack_into(F_RESPONSE_D, packet, HEADER_SIZE, self.secret_d)
        return packet

    # return padded buffer size for payload of length payload_len
    def calc_size(self, payload_len):
        total_size = HEADER_SIZE + payload_len
        if total_size % PADDING != 0:
            total_size += PADDING - (total_size % PADDING)
        return total_size

    # return padded buffer
    # with p_secret and sid set in header
    # buffer: [payload_len | p_secret | STEP | STUDENT_ID]
    def get_buffer_with_header(self, payload_len, p_secret, sid):
        # Set buff size with space for padding
        total_size = self.calc_size(payload_len)

        # Create buff and set header
        buff = bytearray(total_size)
        struct.pack_into(F_HEADER, buff, 0, payload_len, p_secret, STEP, sid)
        return buff

# ///////////////////////// END CLIENTHANDLER ClASS /////////////////////////


# ////////////////////////////// SERVER DRIVER //////////////////////////////
def main():
    server = Server(HOST, PORT)
    server()


if __name__ == '__main__':
    main()
