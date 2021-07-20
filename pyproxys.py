import socket
import select
from kiss_headers import parse_it
from datetime import datetime
from threading import Thread
from typing import Optional
from base64 import b64encode


def http_request_method(request: bytes) -> str:
    return request.split(b" ", 1)[0].decode().strip().upper()


class HttpProxyServer:
    LOG_NONE = 0
    LOG_MIN = 1
    LOG_MID = 2
    LOG_MAX = 3

    server_thread: Optional[Thread]
    server_socket: Optional[socket.socket]
    buffer_size: int
    backlog: int
    _running: bool
    proxy_agent: str
    auth_b64: Optional[set[str]]
    log_level: int

    def __init__(self, buffer_size: int = 1024, backlog: int = 100,
                 auth_list: Optional[list[tuple[str, str]]] = None,
                 proxy_agent: str = "proxys!", log_level=LOG_MIN) -> None:
        self.buffer_size: int = buffer_size
        self.backlog: int = backlog
        self._running: bool = False
        self.proxy_agent = proxy_agent
        self.log_level = log_level
        if auth_list:
            self.auth_b64 = set()
            for auth in auth_list:
                username, password = auth
                # encode with base64
                auth_str = b64encode(f"{username}:{password}".encode()).decode()
                self.auth_b64.add(auth_str)
        else:
            self.auth_b64 = None

    def requires_auth(self) -> bool:
        return self.auth_b64 is not None

    def _send_connect_ok(self, conn: socket.socket) -> None:
        response = b'HTTP/1.1 200 OK Tunnel Created\r\nTimestamp: %s\r\nProxy-Agent: %s\r\n\r\n' % (
            str(datetime.now()).encode(), self.proxy_agent.encode()
        )
        conn.sendall(response)

    def _send_bad_request(self, conn: socket.socket):
        response = b'HTTP/1.1 400 Bad Request\r\nTimestamp: %s\r\nProxy-Agent: %s\r\n\r\n' % (
            str(datetime.now()).encode(), self.proxy_agent.encode()
        )
        conn.sendall(response)

    def _log(self, msg, level):
        if level <= self.log_level:
            print(msg)

    def _send_proxy_auth_required(self, conn: socket.socket):
        response = b'HTTP/1.1 407 Proxy Authentication Required\r\n' \
                   b'Timestamp: %s\r\nProxy-Authenticate: Basic\r\nProxy-Agent: %s\r\n\r\n' % (
                       str(datetime.now()).encode(), self.proxy_agent.encode())
        conn.sendall(response)

    def start(self, host: str, port: int) -> None:
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Initializing the socket
        self.server_socket.bind((host, port))  # Binding the socket to listen at the port
        self.server_socket.listen(self.backlog)  # Start listening for connections
        self._log(f"[+] Server started successfully: {host}:{port}.", HttpProxyServer.LOG_MIN)
        # create background thread for handling incoming connections
        self.server_thread = Thread(target=self._serve, daemon=True)
        self._running = True  # set server running flag
        self.server_thread.start()

    def is_running(self) -> bool:
        return self._running

    def _serve(self) -> None:
        while self.is_running():
            src_conn, src_addr = self.server_socket.accept()  # Accept connection from client browser
            client_thread = Thread(target=self._handle_client, args=(src_conn, src_addr), daemon=True)
            client_thread.start()

    def stop(self):
        self._running = False
        self.server_socket.close()
        self.server_thread = None
        self.server_socket = None
        self._log("[+] Proxy server was stopped.", HttpProxyServer.LOG_MIN)

    def receive_http_request(self, conn: socket.socket) -> bytes:
        request_data = b''
        while self.is_running():
            buffer = conn.recv(self.buffer_size)  # Receive client data
            if len(buffer) > 0:
                request_data += buffer
                # http request ends with "\r\n\r\n", so if buffer ends with this value,
                # it means we have a complete http request
                if buffer.endswith(b"\r\n\r\n"):
                    break
            else:
                break
        return request_data

    def _handle_client(self, src_conn: socket.socket, src_addr: tuple[str, int]) -> None:
        dst_conn = None
        src_host, src_port = src_addr
        self._log(f"[.] {src_host}:{src_port} connected.", HttpProxyServer.LOG_MAX)
        try:
            request_data = self.receive_http_request(src_conn)
            headers = parse_it(request_data)

            if self.requires_auth():
                try:
                    auth_token = str(headers['Proxy-Authorization']).split(" ")[1]
                    if auth_token in self.auth_b64:  # there is such value in the b64 token set
                        self._send_connect_ok(src_conn)
                    else:
                        self._log(
                            f"[-] Proxy server couldn't authenticate {src_host}:{src_port} due to invalid credentials.",
                            HttpProxyServer.LOG_MID
                        )
                        self._send_proxy_auth_required(src_conn)
                        src_conn.close()
                        return
                except KeyError:
                    self._log("[-] Proxy server requires client authentication, "
                              f"yet {src_host}:{src_port} didn't provide a 'Proxy-Authorization' header.",
                              HttpProxyServer.LOG_MID)
                    self._send_proxy_auth_required(src_conn)
                    src_conn.close()
                    return
                except IndexError:
                    self._log(f"[-] Bad 'Proxy-Authorization' header received from {src_host}:{src_port}.",
                              HttpProxyServer.LOG_MID)
                    self._send_proxy_auth_required(src_conn)
                    src_conn.close()
                    return

            try:
                host_header = str(headers["Host"]).strip()
            except KeyError:
                self._log(f"[-] Received malformed request from {src_host}:{src_port}: no 'Host' header found.",
                          HttpProxyServer.LOG_MID)
                self._send_bad_request(src_conn)
                src_conn.close()
                return

            # find destination host and port
            dst = host_header.split(":")
            if len(dst) == 1:
                # if port is not specified, then assume 80, since it's the standard HTTP port
                dst_host = dst[0]
                dst_port = 80
            else:
                dst_host, dst_port = dst
                dst_port = int(dst_port)

            try:
                # try resolve server via dns
                # the function gethostbyname doesn't resolve ip addresses:
                # socket.gethostbyname("192.100.1.32") == "192.100.1.32"
                dst_host = socket.gethostbyname(dst_host)
                dst_addr = (dst_host, dst_port)
                dst_host, dst_port = dst_addr
            except socket.gaierror:
                self._log(f"[-] Unable to resolve host '{dst_host}'.",
                          HttpProxyServer.LOG_MID)
                src_conn.close()
                return

            dst_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dst_conn.connect((dst_host, dst_port))
            while self.is_running():  # while the server is running
                readable, _, _ = select.select([src_conn, dst_conn], [], [], 1)
                for conn in readable:  # for every connection that can be read
                    buffer = conn.recv(self.buffer_size)
                    if len(buffer) > 0:
                        if conn is src_conn:
                            # route traffic from client to server
                            dst_conn.sendall(buffer)
                        elif conn is dst_conn:
                            # route traffic from server to client
                            src_conn.sendall(buffer)
                    else:  # got 0 bytes - connection closed
                        dst_conn.close()
                        src_conn.close()
                        return
        except ConnectionError as err:
            self._log(f"[-] Connection error occurred: {err.strerror}.", HttpProxyServer.LOG_MID)
        except socket.error as err:
            self._log(f"[-] Socket error occurred: {str(err)}.", HttpProxyServer.LOG_MID)
        finally:
            # close sockets regardless
            if dst_conn is not None:
                dst_conn.close()
            src_conn.close()


if __name__ == "__main__":
    server = HttpProxyServer(auth_list=[('tiloh', 'ipidor1')])
    server.start("", 1111)
    input()
    server.stop()
