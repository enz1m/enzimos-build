# SPDX-License-Identifier: MIT
"""Actual private-socket liveness boundaries; no VM or external network."""
import http.client
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract import Invalid
from install_iso_vm import Qmp
from acquire_packages import DeadlineSocket


class DeadlineTests(unittest.TestCase):
    def test_qmp_stalls_fail_but_events_do_not_hide_a_valid_reply(self):
        for mode in ('greeting', 'reply', 'events', 'closed'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)/'fake-qmp'
                listener = socket.socket(socket.AF_UNIX)
                listener.bind(str(path));listener.listen()
                stop = threading.Event()
                def peer():
                    with listener.accept()[0] as stream:
                        if mode == 'greeting':stop.wait(1);return
                        if mode == 'closed':return
                        stream.sendall(b'{"QMP":{}}\n')
                        data = bytearray()
                        while b'\n' not in data:data.extend(stream.recv(4096))
                        if mode == 'reply':stop.wait(1);return
                        stream.sendall(b'{"event":"RESET"}\n{"return":{}}\n')
                        stop.wait(1)
                worker = threading.Thread(target=peer);worker.start()
                try:
                    with patch.object(Qmp, 'IO_TIMEOUT', .05):
                        if mode == 'events':
                            client = Qmp(path);client.file.close();client.sock.close()
                        else:
                            with self.assertRaises(Invalid):Qmp(path)
                finally:
                    stop.set();worker.join(2);listener.close()
                    self.assertFalse(worker.is_alive())

    def test_http_absolute_deadline_bounds_dripping_headers_and_body(self):
        for mode in ('valid', 'header', 'body'):
            with self.subTest(mode=mode):
                reader, writer = socket.socketpair()
                stop = threading.Event()
                header = b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n'
                def peer():
                    try:
                        if mode != 'header':writer.sendall(header)
                        data = header+b'abc' if mode == 'header' else b'abc'
                        if mode == 'valid':writer.sendall(data)
                        else:
                            for byte in data:
                                if stop.wait(.03):break
                                writer.sendall(bytes([byte]))
                    except OSError:pass
                    finally:writer.close()
                worker = threading.Thread(target=peer);worker.start()
                response = http.client.HTTPResponse(DeadlineSocket(reader, time.monotonic()+.05))
                try:
                    if mode == 'valid':
                        response.begin();self.assertEqual(response.read(1024), b'abc')
                    else:
                        with self.assertRaises(TimeoutError):
                            response.begin();response.read(1024)
                finally:
                    response.close();reader.close();stop.set();worker.join(2)
                    self.assertFalse(worker.is_alive())
