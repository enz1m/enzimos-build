#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tiny RFB client: vnc_client.py SOCKET cmd... where cmd is shot:FILE | click:X,Y | type:TEXT | key:NAME | wait:SEC"""
import os, socket, struct, sys, time, zlib

KEYS = {'ret': 0xff0d, 'tab': 0xff09, 'esc': 0xff1b, 'bs': 0xff08, 'down': 0xff54, 'up': 0xff52, 'shift': 0xffe1, 'f1': 0xffbe, 'f2': 0xffbf, 'left': 0xff51, 'right': 0xff53, 'super':0xffeb, 'ctrl': 0xffe3, 'alt': 0xffe9, 'home': 0xff50, 'end': 0xff57, 'delete': 0xffff}

KEYS.update({f"f{i}":0xffbd+i for i in range(1,13)})
KEYS['print'] = 0xff61

def recvn(s, n):
    b = b''
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c: raise EOFError
        b += c
    return b


def connect(path, led_state=True):
    s = socket.socket(socket.AF_UNIX); s.settimeout(20); s.connect(path)
    recvn(s, 12); s.sendall(b'RFB 003.008\n')
    n = recvn(s, 1)[0]; types = recvn(s, n)
    assert 1 in types, types
    s.sendall(b'\x01'); assert struct.unpack('>I', recvn(s, 4))[0] == 0
    s.sendall(b'\x01')
    w, h = struct.unpack('>HH', recvn(s, 4)); recvn(s, 16); nl = struct.unpack('>I', recvn(s, 4))[0]; recvn(s, nl)
    # 32bpp little-endian BGRX
    s.sendall(struct.pack('>BxxxBBBBHHHBBBxxx', 0, 32, 24, 0, 1, 255, 255, 255, 16, 8, 0))
    # Negotiate resizing: firmware, KMS and the desktop may change size while
    # a framebuffer request is in flight.
    # QEMU otherwise infers CapsLock from keysyms, including modified shortcuts.
    encodings = (0, -223, -261) if led_state else (0, -223)
    s.sendall(struct.pack('>BxH' + 'i' * len(encodings), 2, len(encodings), *encodings))
    return s, w, h


def shot(s, w, h, out):
    if not w or not h or w * h > 16 * 1024 * 1024:
        raise ValueError('invalid desktop size')
    fb = bytearray(w * h * 4)
    for attempt in range(4):
        s.sendall(struct.pack('>BBHHHH', 3, 0, 0, 0, w, h))
        while True:
            t = recvn(s, 1)[0]
            if t == 0: break
            if t == 2: continue
            if t == 3:
                recvn(s, 3); ln = struct.unpack('>I', recvn(s, 4))[0]
                if ln > 1024 * 1024: raise ValueError('oversized server clipboard')
                recvn(s, ln); continue
            if t == 1:
                _, cnt = struct.unpack('>xHH', recvn(s, 5))
                recvn(s, cnt * 6); continue
            raise ValueError('unsupported RFB message')
        recvn(s, 1); n = struct.unpack('>H', recvn(s, 2))[0]
        resized = False
        area = 0
        for _ in range(n):
            x, y, rw, rh, enc = struct.unpack('>HHHHi', recvn(s, 12))
            if enc == -261:
                recvn(s, 1)
                continue
            if enc == -223:
                if not rw or not rh or rw * rh > 16 * 1024 * 1024:
                    raise ValueError('invalid desktop size')
                w, h = rw, rh
                fb = bytearray(w * h * 4)
                resized = True
                area = 0
                continue
            if enc != 0 or x + rw > w or y + rh > h:
                raise ValueError('invalid raw framebuffer rectangle')
            data = recvn(s, rw * rh * 4)
            area += rw * rh
            for r in range(rh):
                o = ((y + r) * w + x) * 4
                fb[o:o + rw * 4] = data[r * rw * 4:(r + 1) * rw * 4]
        # A size notification may contain no pixels. Request the complete new
        # surface rather than writing an empty or clipped screenshot.
        if not resized and area >= w * h:
            break
    else:
        raise ValueError('no complete framebuffer after resize')
    rows = b''.join(b'\x00' + bytes(v for i in range(w) for v in (fb[(y*w+i)*4+2], fb[(y*w+i)*4+1], fb[(y*w+i)*4])) for y in range(h))
    ch = lambda k, b: struct.pack('>I', len(b)) + k + b + struct.pack('>I', zlib.crc32(k + b) & 0xffffffff)
    with open(out, 'wb') as stream:
        stream.write(b'\x89PNG\r\n\x1a\n' + ch(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)) + ch(b'IDAT', zlib.compress(rows, 6)) + ch(b'IEND', b''))


def key(s, sym, down):
    s.sendall(struct.pack('>BBxxI', 4, 1 if down else 0, sym))


def main():
    led_state = os.environ.get('ENZIMOS_VNC_LEGACY_LOCK_SYNC') != '1'
    s, w, h = connect(sys.argv[1], led_state)
    for cmd in sys.argv[2:]:
        op, _, arg = cmd.partition(':')
        if op == 'shot':
            # Firmware, splash and desktop can change resolution during one review.
            s.close();s,w,h=connect(sys.argv[1], led_state);shot(s,w,h,arg)
        elif op == 'move':
            x,y=map(int,arg.split(','));s.sendall(struct.pack('>BBHH',5,0,x,y));time.sleep(.5)
        elif op in ('doubleclick', 'tripleclick'):
            x,y=map(int,arg.split(','));s.sendall(struct.pack('>BBHH',5,0,x,y));time.sleep(.1)
            for _ in range(3 if op == 'tripleclick' else 2):
                s.sendall(struct.pack('>BBHH',5,1,x,y));time.sleep(.06)
                s.sendall(struct.pack('>BBHH',5,0,x,y));time.sleep(.06)
            time.sleep(.6)
        elif op in ('click','rightclick'):
            x, y = map(int, arg.split(','))
            s.sendall(struct.pack('>BBHH', 5, 0, x, y)); time.sleep(0.15)
            s.sendall(struct.pack('>BBHH', 5, 4 if op=='rightclick' else 1, x, y)); time.sleep(0.1)
            s.sendall(struct.pack('>BBHH', 5, 0, x, y)); time.sleep(0.6)
        elif op == 'scroll':
            if ',' in arg:x,y,count=map(int,arg.split(','))
            else:x,y,count=900,610,int(arg)
            for _ in range(abs(count)):
                s.sendall(struct.pack('>BBHH',5,16 if count>0 else 8,x,y));time.sleep(.1)
                s.sendall(struct.pack('>BBHH',5,0,x,y));time.sleep(.1)
        elif op == 'drag':
            x,y,tx,ty = map(int, arg.split(','))
            s.sendall(struct.pack('>BBHH',5,0,x,y)); time.sleep(.2)
            s.sendall(struct.pack('>BBHH',5,1,x,y)); time.sleep(.2)
            for i in range(1,21):
                s.sendall(struct.pack('>BBHH',5,1,x+(tx-x)*i//20,y+(ty-y)*i//20)); time.sleep(.04)
            s.sendall(struct.pack('>BBHH',5,0,tx,ty)); time.sleep(.8)
        elif op in ('type','typefile','typefast','typefilefast'):
            if op in ('typefile','typefilefast'):arg=open(arg).read()
            for c in arg:
                up = c.isupper() or c in '|~{}!@#$%^&*()_+:"<>?'
                if up: key(s, KEYS['shift'], True)
                key(s, ord(c), True); key(s, ord(c), False)
                if up: key(s, KEYS['shift'], False)
                time.sleep(0.005 if op in ('typefast','typefilefast') else 0.05)
            time.sleep(0.4)
        elif op in ('chord', 'chordfast'):
            names=arg.split(',');syms=[KEYS[n] if n in KEYS else ord(n) for n in names]
            for sym in syms:key(s,sym,True)
            for sym in reversed(syms):key(s,sym,False)
            if op == 'chord': time.sleep(.3)
        elif op == 'key':
            key(s, KEYS[arg], True); key(s, KEYS[arg], False); time.sleep(0.5)
        elif op == 'wait': time.sleep(float(arg))


if __name__ == '__main__':
    main()
