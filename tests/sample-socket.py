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

if not len(sys.argv) == 3:
    sys.stderr.write(
            'usage: %s '
            '<path to info sample> '
            '<path to stat sample>\n' % sys.argv[0])
    sys.exit(1)

with file(sys.argv[1]) as info:
    data_info = info.read()

with file(sys.argv[2]) as stat:
    data_stat = stat.read()

try:
    os.unlink(SOCKET_PATH)
except:
    pass

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(SOCKET_PATH)
s.listen(1)

conn, addr = s.accept()

while 1:
    data = conn.recv(1024)
    if not data or data == 'quit\n':
        break
    elif data == 'show info\n':
        conn.sendall(data_info)
    elif data == 'show stat\n':
        conn.sendall(data_stat)
    conn.send('\n')
    conn.send(SOCKET_PROMPT)
conn.close()

