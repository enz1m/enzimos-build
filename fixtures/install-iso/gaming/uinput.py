# SPDX-License-Identifier: MIT
"""Guest-only virtual pad; never run against host input devices."""
import fcntl
import os
from pathlib import Path
import struct
import time

fd = os.open('/dev/uinput', os.O_WRONLY | os.O_NONBLOCK)
for value in (1, 3):
    fcntl.ioctl(fd, 0x40045564, value)  # UI_SET_EVBIT
for value in (304, 305, 307, 308):
    fcntl.ioctl(fd, 0x40045565, value)  # UI_SET_KEYBIT
for value in (0, 1):
    fcntl.ioctl(fd, 0x40045567, value)  # UI_SET_ABSBIT
maximum = [32767, 32767] + [0] * 62
minimum = [-32767, -32767] + [0] * 62
body = struct.pack('80sHHHHi', b'enzimOS fixture gamepad', 3, 0x045e, 0x028e, 1, 0)
body += struct.pack('64i', *maximum) + struct.pack('64i', *minimum) + bytes(512)
os.write(fd, body)
fcntl.ioctl(fd, 0x5501)  # UI_DEV_CREATE
Path('/var/tmp/enzimos-gaming-lab/pad-created').touch()
try:
    index = 0
    while True:
        for kind, code, value in [(3, 0, 15000 if index % 2 else -15000),
                                  (1, 304, index % 2), (0, 0, 0)]:
            os.write(fd, struct.pack('llHHi', 0, 0, kind, code, value))
        index += 1
        time.sleep(.1)
finally:
    fcntl.ioctl(fd, 0x5502)
    os.close(fd)
