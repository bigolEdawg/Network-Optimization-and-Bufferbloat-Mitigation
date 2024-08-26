import socket
import struct
import sys
import select

# ////////////////////////////// CLIENT DATA //////////////////////////////
HOST = "attu2.cs.washington.edu" if len(sys.argv) < 2 else sys.argv[1]
PORT_A = 12235
TIMEOUT = .5
# /////////////////////////////////////////////////////////////////////////

# ////////////////////////////// PACKET DATA //////////////////////////////
STUDENT_ID = 930
STEP = 1
HEADER_SIZE = 12
MESSAGE_A = "hello world\0"
PADDING = 4
# /////////////////////////////////////////////////////////////////////////

# ////////////////////////////// FORMAT DATA //////////////////////////////
# expected format for packets
F_HEADER = "!2I2H"                                  # header format
F_MESSAGE_A = "!" + str(len(MESSAGE_A)) + "s"       # stage a send payload
F_RESPONSE_A = "!4I"                                # stage a recv payload
F_MESSAGE_B = "!I"                                  # stage b send payload
F_ACK_B = "!I"                                      # stage b recv acknowledgement
F_RESPONSE_B = "!2I"                                # stage b recv payload
F_RESPONSE_C = "!3Ic"                               # stage c recv payload
F_MESSAGE_D = "!c"                                  # stage d send payload
F_RESPONSE_D = "!I"                                 # stage d recv payload
# //////////////////////////////////////////////////////////////////////////


# run the client
def main():
    # create udp socket, connect, and run stage a
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((HOST, PORT_A))
        response = stage_a(s)
    num, length, port_b, secret_a = response
    print("Secret A:", secret_a)

    # create udp socket, connect, and run stage b
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((HOST, port_b))
        response = stage_b(s, length, secret_a, num)
    tcp_port, secret_b = response
    print("Secret B:", secret_b)

    # create tcp socket, connect, and run stage c and d
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, tcp_port))
        response = stage_c(s)
        num2, len2, secret_c, c = response
        print("Secret C: ", secret_c)
        response = stage_d(s, num2, len2, secret_c, c)
    secret_d, = response
    print("Secret D: ", secret_d)


# send packet with payload MESSAGE_A
# receive server response
# return response
def stage_a(s):
    # send packet
    packet = get_buffer_with_header(len(MESSAGE_A), 0)
    struct.pack_into(F_MESSAGE_A, packet, HEADER_SIZE, MESSAGE_A.encode('UTF-8'))
    s.sendall(packet)

    # process response
    data = s.recv(get_total_bytes(struct.calcsize(F_RESPONSE_A)))
    response = struct.unpack_from(F_RESPONSE_A, data, HEADER_SIZE)
    return response


# send num packets with payload length=length
# retransmit after TIMEOUT until we receive an ack
# receive server response
# return response
def stage_b(s, length, secret_a, num):
    packet = get_buffer_with_header(length + struct.calcsize(F_MESSAGE_B), secret_a)
    # send num packets
    for i in range(num):
        struct.pack_into(F_MESSAGE_B, packet, HEADER_SIZE, i)
        s.sendall(packet)

        # retransmit after TIMEOUT if no ack
        while True:
            r, w, x = select.select([s], [], [], TIMEOUT)
            # we have an ack -> verify
            if r:
                data = s.recv(get_total_bytes(struct.calcsize(F_ACK_B)))
                response = struct.unpack_from(F_ACK_B, data, HEADER_SIZE)
                ack_id, = response
                if ack_id == i:
                    break
            #  we didn't get an ack -> send again
            s.sendall(packet)

    # process server response
    data = s.recv(HEADER_SIZE + struct.calcsize(F_RESPONSE_B))
    response = struct.unpack_from(F_RESPONSE_B, data, HEADER_SIZE)
    return response


# receive server response
# return response
def stage_c(s):
    response_len = get_total_bytes(struct.calcsize(F_RESPONSE_C))
    data = s.recv(response_len)
    response = struct.unpack_from(F_RESPONSE_C, data, HEADER_SIZE)
    return response


# send num2 packets with payload of length len2 filled with char c
# receive server response
# return response
def stage_d(s, num2, len2, secret_c, c):
    packet = get_buffer_with_header(len2, secret_c)
    # stuff char c into packet
    for i in range(len2):
        struct.pack_into(F_MESSAGE_D, packet, HEADER_SIZE + i, c)

    # send num2 packets
    for i in range(num2):
        s.sendall(packet)

    # process server response
    response_len = get_total_bytes(struct.calcsize(F_RESPONSE_D))
    data = s.recv(response_len)
    response = struct.unpack_from(F_RESPONSE_D, data, HEADER_SIZE)
    return response


# return a padded buffer for a packet of size HEADER_SIZE + payload_len
# with p_secret set in header
# buffer: [payload_len | p_secret | STEP | STUDENT_ID]
def get_buffer_with_header(payload_len, p_secret):
    # Set buff size with space for padding
    total_size = get_total_bytes(payload_len)

    # Create buff and set header
    buff = bytearray(total_size)
    struct.pack_into(F_HEADER, buff, 0, payload_len, p_secret, STEP, STUDENT_ID)
    return buff


# pad payload_len to multiple of PADDING
def get_total_bytes(payload_len):
    total_size = HEADER_SIZE + payload_len
    if total_size % PADDING != 0:
        total_size += PADDING - (total_size % PADDING)
    return total_size


if __name__ == '__main__':
    main()
