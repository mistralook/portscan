import socket
import argparse
import struct
import time
from multiprocessing import Pool
from random import randint


class Portscan:
    def __init__(self):
        self.parser_args = create_parser().parse_args()
        self.thread_num = 0
        self.timeout = self.parser_args.timeout
        self.verbose = self.parser_args.verbose
        self.guess = self.parser_args.guess
        self.ip_address = self.parser_args.IP_ADDRESS

    def portscan(self, udp_ports, tcp_ports):
        self.get_open_udp_ports(udp_ports)
        self.get_open_tcp_ports(tcp_ports)

    def get_open_udp_ports(self, udp_ports):
        open_udp = []
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_ICMP)
        icmp_sock.bind(('127.0.0.1', 10000))
        icmp_sock.settimeout(self.timeout)
        for ports in udp_ports:
            for port in ports:
                for tries in range(3):
                    udp_sock.sendto(b'data', (self.ip_address, int(port)))
                    try:
                        icmp_sock.recv(100)
                    except socket.timeout:
                        open_udp.append(port)
                        break
        for port in open_udp:
            if self.guess:
                proto = self.define_udp_protocol(udp_sock, int(port))
                proto = '-' if proto is None else proto
                print(f'UDP {port} {proto}')
            else:
                print(f'UDP {port}')

    def get_open_tcp_ports(self, tcp_ports):
        open_tcp = []
        elapsed_time = dict()
        for ports in tcp_ports:
            for port in ports:
                tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM,
                                         socket.IPPROTO_TCP)
                tcp_sock.settimeout(self.timeout)
                start = time.time()
                try:
                    tcp_sock.connect((self.ip_address, port))
                    tcp_sock.shutdown(socket.SHUT_RD)
                except socket.timeout:
                    continue
                elapsed = time.time() - start
                elapsed_time[port] = elapsed * 1000
                open_tcp.append(port)

        for port in open_tcp:
            proto = self.define_tcp_protocol(int(port))
            proto = '-' if proto is None else proto
            if self.guess and self.verbose:
                print(f'TCP {port} {elapsed_time[port]:0.3f} {proto}')
            elif self.guess:
                print(f'TCP {port} {proto}')
            elif self.verbose:
                print(f'TCP {port} {elapsed_time[port]:0.3f}')
            else:
                print(f'TCP {port}')



    def define_tcp_protocol(self, port):
        requests, ID = get_requests()
        for request_type in requests.keys():
            tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_sock.settimeout(1)
            tcp_sock.connect((self.ip_address, port))
            tcp_sock.send(requests[request_type])
            try:
                data = tcp_sock.recv(2048)
                if data is not None:
                    proto = define_answer_type(data, ID,
                                               requests[request_type])
                    return proto
            except socket.timeout:
                pass
            tcp_sock.shutdown(socket.SHUT_RD)

    def define_udp_protocol(self, sock, port):
        requests, ID = get_requests()
        for request_type in requests.keys():
            sock.settimeout(self.timeout)
            sock.sendto(requests[request_type], (self.ip_address, port))
            try:
                data = sock.recv(2048)
                if data is not None:
                    proto = define_answer_type(data, ID,
                                               requests[request_type])
                    return proto
            except socket.timeout:
                pass


def define_answer_type(data, ID, sended_data):
    if data[:4].startswith(b'HTTP'):
        return 'HTTP'
    elif struct.pack('!H', ID) in data:
        return 'DNS'
    elif data == sended_data:
        return 'ECHO'
    else:
        return '-'


def get_requests():
    ID = randint(1, 65535)
    dns_request = struct.pack("!HHHHHH", ID, 256, 1, 0, 0, 0)
    dns_request += b"\x06google\x03com\x00\x00\x01\x00\x01"
    requests = {'HTTP': b'GET / HTTP/1.1',
                'DNS': dns_request,
                'ECHO': b'hello'
                }
    return requests, ID


def main():
    parser = create_parser()
    args = parser.parse_args()
    ps = Portscan()
    pairs = get_pairs(args.ports_and_protocols)
    udp = get_ports(pairs, 'udp')
    tcp = get_ports(pairs, 'tcp')
    ps.portscan(udp, tcp)


def get_ports(protocols_and_ports, proto):
    ports = []
    for pair in protocols_and_ports:
        if proto in pair:
            ports.append(pair[1])
    if ports:
        ports = ','.join(ports)
        segment_range = lambda x, y: range(x, y + 1)
        ports = map(list, [segment_range(*map(int, chunk.split('-')))
                           if '-' in chunk else [int(chunk)]
                           for chunk in ports.split(',')])
    return ports


def get_pairs(pairs):
    ports_list = []
    for pair in pairs:
        proto_and_port = pair.split('/')
        protocol = proto_and_port[0]
        ports = proto_and_port[1]
        ports_list.append((protocol, ports))
    return ports_list


def create_parser():
    ps = argparse.ArgumentParser(prog='porstcan.py',
                                 usage='sudo python %(prog)s '
                                       '[OPTIONS] '
                                       'IP_ADDR '
                                       '[{tcp|udp}[/[PORT|PORT-PORT],...]]...')
    ps.add_argument('IP_ADDRESS', help='host address')
    ps.add_argument('-g', '--guess', action="store_true",
                    help='defining the application layer protocol ')
    ps.add_argument('--timeout', help='timeout for response waiting',
                    default=2, type=float)
    ps.add_argument('-j', '--num-threads',
                    help='number of threads',
                    type=int)
    ps.add_argument('-v', '--verbose', action="store_true",
                    help='detailed answer')
    ps.add_argument('ports_and_protocols', nargs='+',
                    help='[{tcp|udp}[/[PORT|PORT-PORT],...]]...')

    return ps


if __name__ == "__main__":
    main()
