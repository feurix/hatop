#!/usr/bin/env python
# Thu Apr 08 16:51:58 CEST 2010 John Feuerstein <john@feurix.com>
#
# This script emulates the haproxy stats unix socket to help in
# hatop development and to provide some (fake) sample data.

SOCKET_PATH='sample-socket.sock'
SOCKET_PROMPT='> '

import os
import socket
import sys
import time

if not len(sys.argv) == 3:
    sys.stderr.write(
            'usage: %s '
            '<path to info sample> '
            '<path to stat sample>\n' % sys.argv[0])
    sys.exit(1)

def read_info():
    with file(sys.argv[1]) as info:
        data = info.read()
    return data

def read_stat():
    with file(sys.argv[2]) as stat:
        data = stat.read()
    return data

try:
    os.unlink(SOCKET_PATH)
except:
    pass

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(SOCKET_PATH)
s.listen(1)

while 1:
    conn, addr = s.accept()

    while 1:
        data = conn.recv(1024).strip()
        print('--- %s' % time.ctime())
        print('<<< %s' % data)
        if not data:
            continue
        if data == 'quit':
            break
        elif data.startswith('show info'):
            print('>>> info...')
            conn.sendall(read_info())
        elif data.startswith('show stat'):
            print('>>> stat...')
            conn.sendall(read_stat())
        print('>>> empty line (end of response)')
        conn.sendall('\n')
        print('>>> prompt')
        conn.sendall(SOCKET_PROMPT)
        print('--- %s\n' % time.ctime())

    conn.close()

