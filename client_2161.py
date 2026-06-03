#!/usr/bin/env python3
"""
IE2102 - Network Programming Assignment
Student : IT24102161
Client  : client_2161.py
Server  : localhost:50161
"""

import socket
import sys

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 50161

# Fix: use a module-level dict keyed by socket fd instead of setting
# attributes directly on the socket object (which raises AttributeError).
_recv_buffers = {}


def send_framed(sock: socket.socket, payload: str) -> None:
    """Send a LEN-framed message to the server."""
    data = payload.encode()
    header = f"LEN:{len(data)}\n".encode()
    sock.sendall(header + data)


def recv_response(sock: socket.socket) -> str:
    """
    Receive one newline-terminated response line from the server.
    Leftover bytes are kept in _recv_buffers[fd] between calls so no
    data is lost under TCP segmentation or back-to-back responses.
    """
    fd = sock.fileno()
    if fd not in _recv_buffers:
        _recv_buffers[fd] = bytearray()

    buf = _recv_buffers[fd]

    while True:
        nl = buf.find(b"\n")
        if nl != -1:
            line = bytes(buf[:nl])
            del buf[:nl + 1]           # consume line + newline, keep rest
            return line.decode(errors="replace").strip()

        chunk = sock.recv(4096)
        if not chunk:
            # Connection closed — return whatever remains
            line = bytes(buf)
            buf.clear()
            return line.decode(errors="replace").strip()
        buf.extend(chunk)


def print_banner():
    print("=" * 55)
    print("  IE2102 Network Programming Client — IT24102161")
    print(f"  Server: {SERVER_HOST}:{SERVER_PORT}")
    print("=" * 55)
    print("Commands: REGISTER <user> <pass>")
    print("          LOGIN    <user> <pass>")
    print("          LOGOUT")
    print("          PING                    (requires login)")
    print("          QUIT")
    print("=" * 55)


def main():
    print_banner()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"[+] Connected to {SERVER_HOST}:{SERVER_PORT}\n")
    except ConnectionRefusedError:
        print(f"[!] Cannot connect to {SERVER_HOST}:{SERVER_PORT}")
        print("    Make sure the server is running.")
        sys.exit(1)

    try:
        while True:
            try:
                cmd = input("client> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[*] Disconnecting…")
                break

            if not cmd:
                continue

            # Validate payload size before sending
            if len(cmd.encode()) > 4096:
                print("[!] Payload too large (max 4096 bytes). Not sent.")
                continue

            send_framed(sock, cmd)
            response = recv_response(sock)
            print(f"server> {response}")

            # Exit on QUIT/EXIT
            if cmd.upper() in ("QUIT", "EXIT"):
                break

    finally:
        _recv_buffers.pop(sock.fileno(), None)  # clean up buffer entry
        sock.close()
        print("[*] Connection closed.")


if __name__ == "__main__":
    main()
