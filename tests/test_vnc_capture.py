# SPDX-License-Identifier: MIT
"""Protocol fixtures for the actual installer/recovery visual capture client."""
import importlib.util
from pathlib import Path
import socket
import struct
import tempfile
import unittest
import zlib

spec = importlib.util.spec_from_file_location('installer_vnc_capture', Path(__file__).resolve().parents[1] / 'vnc_client.py')
vnc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vnc)


def update(rectangles):
    return b'\0\0' + struct.pack('>H', len(rectangles)) + b''.join(rectangles)


def rectangle(w, h, encoding=0, pixels=b'', x=0, y=0):
    return struct.pack('>HHHHi', x, y, w, h, encoding) + pixels


class VncCaptureTests(unittest.TestCase):
    def capture(self, packets, width=2, height=1):
        client, server = socket.socketpair()
        client.settimeout(1)
        with client, server, tempfile.TemporaryDirectory() as directory:
            server.sendall(packets)
            out = Path(directory) / 'shot.png'
            vnc.shot(client, width, height, out)
            data = out.read_bytes()
            dimensions = struct.unpack('>II', data[16:24])
            offset = 8; compressed = b''
            while offset < len(data):
                size = struct.unpack('>I', data[offset:offset+4])[0]
                if data[offset+4:offset+8] == b'IDAT':compressed += data[offset+8:offset+8+size]
                offset += size + 12
            return dimensions, zlib.decompress(compressed)

    def test_resize_only_notification_requests_complete_new_surface(self):
        pixels = bytes([0,10,20,0]) * 3
        packets = update([rectangle(3,1,-223)]) + update([rectangle(3,1,pixels=pixels)])
        dimensions, rows = self.capture(packets)
        self.assertEqual(dimensions, (3,1))
        self.assertEqual(rows, b'\0' + bytes([20,10,0])*3)

    def test_out_of_bounds_raw_rectangle_refuses(self):
        with self.assertRaises(ValueError):
            self.capture(update([rectangle(3,1)]))
