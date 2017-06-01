import logging
import SocketServer
import time

logging.basicConfig(level=logging.DEBUG,
                    format='%(name)s: %(message)s',
                    )

logger = logging.getLogger(__name__)


class EchoRequestHandlerTCP(SocketServer.BaseRequestHandler):
    def handle(self):
        logger.debug('handle')
        # Echo the back to the client
        data = self.request.recv(1024)
        logger.debug('received (tcp) from %s: "%s"',
                     self.client_address, data)
        self.request.send(data)
        return


class EchoRequestHandlerUDP(SocketServer.BaseRequestHandler):
    def handle(self):
        logger.debug('handle')

        # Echo the back to the client
        data = self.request[0]
        socket = self.request[1]
        logger.debug('received (udp) from %s: "%s"',
                     self.client_address, data)
        socket.sendto(data, self.client_address)
        return


class EchoServerTCP(SocketServer.TCPServer):
    def serve_forever(self):
        logger.info('waiting for tcp request')
        while True:
            self.handle_request()
        return


class EchoServerUDP(SocketServer.UDPServer):
    def serve_forever(self):
        logger.info('waiting for udp request')
        while True:
            self.handle_request()
        return


if __name__ == '__main__':
    import socket
    import threading

    def check_socket(sock):
        # Send the data
        message = 'Hello world'
        logger.debug('sending data: "%s"', message)
        len_sent = sock.send(message)

        # Receive a response
        logger.debug('waiting for response')
        response = sock.recv(len_sent)
        logger.debug('response from server: "%s"', response)

    tcp_addr = "0.0.0.0"
    tcp_port = 80
    udp_addr = "0.0.0.0"
    udp_port = 69

    tcp_server = EchoServerTCP((tcp_addr, tcp_port), EchoRequestHandlerTCP)
    udp_server = EchoServerUDP((udp_addr, udp_port), EchoRequestHandlerUDP)

    try:
        t1 = threading.Thread(target=tcp_server.serve_forever)
        t1.setDaemon(True)  # don't hang on exit
        t1.start()
        t2 = threading.Thread(target=udp_server.serve_forever)
        t2.setDaemon(True)  # don't hang on exit
        t2.start()

        logger.info('TCP Server on %s:%s', tcp_addr, tcp_port)
        logger.info('UDP Server on %s:%s', udp_addr, udp_port)

        logger.debug('checking tcp server')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.debug('connecting to server')
        s.connect((tcp_addr, tcp_port))
        check_socket(s)
        s.close()

        logger.debug('checking udp server')
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        logger.debug('connecting to server')
        s.connect((udp_addr, udp_port))
        check_socket(s)
        s.close()
        while True:
            time.sleep(10)
    finally:
        # Clean up
        logger.debug('done')
        tcp_server.socket.close()
        udp_server.socket.close()
        logger.debug('closed sockets')
