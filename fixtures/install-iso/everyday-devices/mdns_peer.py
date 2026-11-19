# SPDX-License-Identifier: MIT
"""Receive only a test nonce in a guest namespace; never contact a real LAN."""
from pathlib import Path
import socket
import struct
import sys
import time

family, prefix, token = sys.argv[1:]
s = socket.socket(socket.AF_INET if family == '4' else socket.AF_INET6, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
if family == '4':
    s.bind(('', 5353))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                 socket.inet_aton('224.0.0.251') + socket.inet_aton('10.77.0.1'))
else:
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind(('::', 5353))
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                 socket.inet_pton(socket.AF_INET6, 'ff02::fb') + struct.pack('@I', socket.if_nametoindex('portal-peer')))
Path(prefix + '.ready').touch()
end = time.monotonic() + 3
seen = False
while time.monotonic() < end:
    s.settimeout(max(.01, end - time.monotonic()))
    try:
        data, address = s.recvfrom(2048)
    except TimeoutError:
        break
    if data == token.encode():
        seen = True
        break
Path(prefix + '.result').write_text('yes' if seen else 'no')
