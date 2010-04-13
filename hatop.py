#!/usr/bin/env python
#
# Copyright (C) 2010 John Feuerstein <john@feurix.com>
#
#   Project URL: http://feurix.org/projects/hatop/
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
'''
HATop is an interactive ncurses client for the HAProxy stats socket
===================================================================

HATop's appearance is similar to top(1). It supports various modes
for detailed statistics of all configured proxies and services in near
realtime. In addition, it features an interactive CLI for the haproxy
unix socket. This allows administrators to control the given haproxy
instance (change server weight, put servers into maintenance mode, ...)
directly out of hatop and monitor the results immediately.

Note: It is important to understand that when multiple haproxy processes
      are started on the same socket, any process may pick up the request
      and thus hatop will output stats owned solely by that process.
      The current haproxy-internal process id is displayed top right.

Key Mode    Description

1   STATUS  The default mode with health, session and queue statistics
2   TRAFFIC Display connection and request rates as well as traffic stats
3   HTTP    Display various statistical information related to HTTP
4   ERRORS  Display health info, various error counters and downtimes
5   CLI     Display embedded command line client for the unix socket
Hh? HELP    Display this help screen
Qq  -       Quit

Header reference:

Node        configured name of the haproxy node
Uptime      runtime since haproxy was initially started
Pipes       pipes are currently used for kernel-based tcp slicing
Procs       number of haproxy processes
Tasks       number of actice process tasks
Queue       number of queued process tasks (run queue)
Proxies     number of configured proxies
Services    number of configured services

In multiple modes:

NAME        name of the proxy and his services
W           configured weight of the service
STATUS      service status (UP/DOWN/NOLB/MAINT/MAINT(via)...)
CHECK       status of last health check (see status reference below)

In STATUS mode:

ACT         server is active (server), number of active servers (backend)
BCK         server is backup (server), number of backup servers (backend)
QCUR        current queued requests
QMAX        max queued requests
SCUR        current sessions
SMAX        max sessions
SLIM        sessions limit
STOT        total sessions

In TRAFFIC mode:

LBTOT       total number of times a server was selected
RATE        number of sessions per second over last elapsed second
RLIM        limit on new sessions per second
RMAX        max number of new sessions per second
BIN         bytes in (IEEE 1541-2002)
BOUT        bytes out (IEEE 1541-2002)

In HTTP mode:

RATE        HTTP requests per second over last elapsed second
RMAX        max number of HTTP requests per second observed
RTOT        total number of HTTP requests received
1xx         number of HTTP responses with 1xx code
2xx         number of HTTP responses with 2xx code
3xx         number of HTTP responses with 3xx code
4xx         number of HTTP responses with 4xx code
5xx         number of HTTP responses with 5xx code
?xx         number of HTTP responses with other codes (protocol error)

In ERRORS mode:

CF          number of failed checks
CD          number of UP->DOWN transitions
CL          last status change
ECONN       connection errors
EREQ        request errors
ERSP        response errors
DREQ        denied requests
DRSP        denied responses
DOWN        total downtime

Health check status reference:

UNK         unknown
INI         initializing
SOCKERR     socket error
L4OK        check passed on layer 4, no upper layers testing enabled
L4TMOUT     layer 1-4 timeout
L4CON       layer 1-4 connection problem, for example
            "Connection refused" (tcp rst) or "No route to host" (icmp)
L6OK        check passed on layer 6
L6TOUT      layer 6 (SSL) timeout
L6RSP       layer 6 invalid response - protocol error
L7OK        check passed on layer 7
L7OKC       check conditionally passed on layer 7, for example 404 with
            disable-on-404
L7TOUT      layer 7 (HTTP/SMTP) timeout
L7RSP       layer 7 invalid response - protocol error
L7STS       layer 7 response error, for example HTTP 5xx
'''
__author__    = 'John Feuerstein <john@feurix.com>'
__copyright__ = 'Copyright (C) 2010 %s' % __author__
__license__   = 'GNU GPLv3'
__version__   = '0.3.7'

import curses
import os
import re
import sys
import time

# ------------------------------------------------------------------------- #
#                               GLOBALS                                     #
# ------------------------------------------------------------------------- #

# Settings of interactive command session over the unix-socket
HAPROXY_CLI_BUFSIZE = 4096
HAPROXY_CLI_TIMEOUT = 60
HAPROXY_CLI_PROMPT = '> '
HAPROXY_CLI_MAXLINES = 1000

# Screen setup
SCREEN_XMIN = 78
SCREEN_YMIN = 20
SCREEN_XMAX = 200
SCREEN_YMAX = 200
SCREEN_HPOS = 11


HAPROXY_INFO_RE = {
'software_name':    re.compile('^Name:\s*(?P<value>\S+)'),
'software_version': re.compile('^Version:\s*(?P<value>\S+)'),
'software_release': re.compile('^Release_date:\s*(?P<value>\S+)'),
'nproc':            re.compile('^Nbproc:\s*(?P<value>\d+)'),
'procn':            re.compile('^Process_num:\s*(?P<value>\d+)'),
'pid':              re.compile('^Pid:\s*(?P<value>\d+)'),
'uptime':           re.compile('^Uptime:\s*(?P<value>[\S ]+)$'),
'maxconn':          re.compile('^Maxconn:\s*(?P<value>\d+)'),
'curconn':          re.compile('^CurrConns:\s*(?P<value>\d+)'),
'maxpipes':         re.compile('^Maxpipes:\s*(?P<value>\d+)'),
'curpipes':         re.compile('^PipesUsed:\s*(?P<value>\d+)'),
'tasks':            re.compile('^Tasks:\s*(?P<value>\d+)'),
'runqueue':         re.compile('^Run_queue:\s*(?P<value>\d+)'),
'node':             re.compile('^node:\s*(?P<value>\S+)'),
'description':      re.compile('^description:\s*(?P<value>\S+)'),
}

HAPROXY_STAT_MAX_SERVICES = 100 # parser limit
HAPROXY_STAT_COMMENT = '#'
HAPROXY_STAT_SEP = ','
HAPROXY_STAT_CSV = [
# Note: Fields must be listed in correct order, as described in:
# http://haproxy.1wt.eu/download/1.4/doc/configuration.txt [9.1]

# TYPE  FIELD

(str,   'pxname'),          # proxy name
(str,   'svname'),          # service name (FRONTEND / BACKEND / name)
(int,   'qcur'),            # current queued requests
(int,   'qmax'),            # max queued requests
(int,   'scur'),            # current sessions
(int,   'smax'),            # max sessions
(int,   'slim'),            # sessions limit
(int,   'stot'),            # total sessions
(int,   'bin'),             # bytes in
(int,   'bout'),            # bytes out
(int,   'dreq'),            # denied requests
(int,   'dresp'),           # denied responses
(int,   'ereq'),            # request errors
(int,   'econ'),            # connection errors
(int,   'eresp'),           # response errors (among which srv_abrt)
(int,   'wretr'),           # retries (warning)
(int,   'wredis'),          # redispatches (warning)
(str,   'status'),          # status (UP/DOWN/NOLB/MAINT/MAINT(via)...)
(int,   'weight'),          # server weight (server), total weight (backend)
(int,   'act'),             # server is active (server),
                            # number of active servers (backend)
(int,   'bck'),             # server is backup (server),
                            # number of backup servers (backend)
(int,   'chkfail'),         # number of failed checks
(int,   'chkdown'),         # number of UP->DOWN transitions
(int,   'lastchg'),         # last status change (in seconds)
(int,   'downtime'),        # total downtime (in seconds)
(int,   'qlimit'),          # queue limit
(int,   'pid'),             # process id
(int,   'iid'),             # unique proxy id
(int,   'sid'),             # service id (unique inside a proxy)
(int,   'throttle'),        # warm up status
(int,   'lbtot'),           # total number of times a server was selected
(int,   'tracked'),         # id of proxy/server if tracking is enabled
(int,   'type'),            # (0=frontend, 1=backend, 2=server, 3=socket)
(int,   'rate'),            # number of sessions per second
                            # over the last elapsed second
(int,   'rate_lim'),        # limit on new sessions per second
(int,   'rate_max'),        # max number of new sessions per second
(str,   'check_status'),    # status of last health check
(int,   'check_code'),      # layer5-7 code, if available
(int,   'check_duration'),  # time in ms took to finish last health check
(int,   'hrsp_1xx'),        # http responses with 1xx code
(int,   'hrsp_2xx'),        # http responses with 2xx code
(int,   'hrsp_3xx'),        # http responses with 3xx code
(int,   'hrsp_4xx'),        # http responses with 4xx code
(int,   'hrsp_5xx'),        # http responses with 5xx code
(int,   'hrsp_other'),      # http responses with other codes (protocol error)
(str,   'hanafail'),        # failed health checks details
(int,   'req_rate'),        # HTTP requests per second
(int,   'req_rate_max'),    # max number of HTTP requests per second
(int,   'req_tot'),         # total number of HTTP requests received
(int,   'cli_abrt'),        # number of data transfers aborted by client
(int,   'srv_abrt'),        # number of data transfers aborted by server
]
HAPROXY_STAT_NUMFIELDS = len(HAPROXY_STAT_CSV)
HAPROXY_STAT_CSV = [(k, v) for k, v in enumerate(HAPROXY_STAT_CSV)]

# All big numeric values on the screen are prefixed using the metric prefix
# set, while everything byte related is prefixed using binary prefixes.
# Note: If a non-byte numeric value fits into the field, we skip prefixing.
PREFIX_BINARY = {
        1024:    'K',
        1024**2: 'M',
}
PREFIX_METRIC = {
        1000:    'k',
        1000**2: 'M',
        1000**3: 'G',
}
PREFIX_TIME = {
        60:      'm',
        60*60:   'h',
        60*60*24:'d',
}

SPACE = ' '
READ_ONLY = False

# ------------------------------------------------------------------------- #
#                           CLASS DEFINITIONS                               #
# ------------------------------------------------------------------------- #

class HAProxySocket:

    def __init__(self, path):
        self.path = path

        from socket import socket, AF_UNIX, SOCK_STREAM
        self._socket = socket(AF_UNIX, SOCK_STREAM)
        self._socket.settimeout(1)

    def connect(self):
        # Initialize interactive socket connection
        self._socket.connect(self.path)
        self.send('prompt')
        self.wait()
        self.send('set timeout cli %d' % HAPROXY_CLI_TIMEOUT)
        self.wait()

    def close(self):
        try:
            self.send('quit')
        except:
            pass
        try:
            self._socket.close()
        except:
            pass

    def send(self, cmdline):
        self._socket.sendall('%s\n' % cmdline)

    def wait(self):
        # Wait for the prompt and discard data.
        rbuf = ''
        while not rbuf.endswith(HAPROXY_CLI_PROMPT):
            rbuf = rbuf[-(len(HAPROXY_CLI_PROMPT)-1):] + \
                    self._socket.recv(HAPROXY_CLI_BUFSIZE)

    def recv(self):
        # Receive lines until HAPROXY_CLI_MAXLINES or the prompt is reached.
        # If the prompt was not found, discard data and wait for it.
        linecount = 0
        rbuf = ''
        while not rbuf.endswith(HAPROXY_CLI_PROMPT):
            if linecount == HAPROXY_CLI_MAXLINES:
                rbuf = rbuf[-(len(HAPROXY_CLI_PROMPT)-1):] + \
                        self._socket.recv(HAPROXY_CLI_BUFSIZE)
                continue
            rbuf += self._socket.recv(HAPROXY_CLI_BUFSIZE)
            while linecount < HAPROXY_CLI_MAXLINES and '\n' in rbuf:
                line, rbuf = rbuf.split('\n', 1)
                linecount += 1
                yield line

    def get_stat(self):
        self.send('show stat')
        return parse_stat(self.recv())

    def get_info(self):
        self.send('show info')
        return parse_info(self.recv())


class HAProxyData:

    def __init__(self, socket):
        self.socket = socket
        self.pxcount = self.svcount = 0
        self.info = self.stat = {}
        self.lines = []

    def update_info(self):
        self.info = self.socket.get_info()

    def update_stat(self):
        self.stat, self.pxcount, self.svcount = self.socket.get_stat()

    def update_lines(self):
        self.lines = get_lines(self.stat)


class Screen:

    def __init__(self):
        self.xmin = 0
        self.xmax = SCREEN_XMIN
        self.ymin = 0
        self.ymax = SCREEN_YMIN
        self.vmin = 0
        self.cmin = 0
        self.cpos = 0
        self.hpos = SCREEN_HPOS
        self.screen = curses_init()
        curses.def_prog_mode()

    def setup(self):
        self.screen.keypad(1)
        self.screen.nodelay(1)
        self.screen.idlok(1)
        self.screen.move(0, 0)

    def reset(self):
        curses_reset(self.screen)

    def recover(self):
        curses.reset_prog_mode()

    def refresh(self):
        self.screen.noutrefresh()

    def clear(self):
        self.screen.erase()

    # Proxies
    def getch(self, *args, **kwargs):
        return self.screen.getch(*args, **kwargs)
    def hline(self, *args, **kwargs):
        return self.screen.hline(*args, **kwargs)
    def addstr(self, *args, **kwargs):
        return self.screen.addstr(*args, **kwargs)

    @property
    def smin(self):
        return self.hpos + 2

    @property
    def smax(self):
        return self.ymax - 2

    @property
    def cmax(self):
        return self.smax - self.smin - 1

    @property
    def vpos(self):
        return self.vmin + self.cpos

    @property
    def vmax(self):
        return self.vmin + self.cmax

    def sync_size(self):
        updated = False
        ymax, xmax = self.screen.getmaxyx()
        if xmax < SCREEN_XMIN or ymax < SCREEN_YMIN:
            raise RuntimeError('screen too small, need at least %dx%d' % (
                    SCREEN_XMIN, SCREEN_YMIN))
        if xmax != self.xmax:
            self.xmax = min(xmax, SCREEN_XMAX)
            updated = True
        if ymax != self.ymax:
            self.ymax = min(ymax, SCREEN_YMAX)
            updated = True
        return updated


class ScreenPad:

    def __init__(self, screen, xmin, xmax, ymin, ymax):
        self.screen = screen
        self.xmin = xmin
        self.xmax = xmax
        self.ymin = ymin
        self.ymax = ymax
        self.xpos = 0
        self.ypos = 0
        self.pad = curses.newpad(self.ymax + 1, self.xmax + 1)

    def addstr(self, *args, **kwargs):
        return self.pad.addstr(*args, **kwargs)

    def refresh(self):
        self.pad.noutrefresh(self.ypos, self.xpos,
                self.screen.smin,
                self.screen.xmin + 1,
                self.screen.smax - 1,
                self.screen.xmax - 1)


class ScreenMode:

    def __init__(self, name):
        self.name = name
        self.columns = []

    def sync_size(self, screen):
        for idx, column in enumerate(self.columns):
            column.width = get_width(column.minwidth, screen.xmax,
                    len(self.columns), idx)


class ScreenColumn:

    def __init__(self, name, header, minwidth, maxwidth, align, filters={}):
        self.name = name
        self.header = header
        self.align = align
        self.minwidth = minwidth
        self.maxwidth = maxwidth
        self.width = minwidth
        self.filters = {'always': [], 'ondemand': []}
        self.filters.update(filters)

    def get_width(self):
        return self._width

    def set_width(self, n):
        if self.maxwidth:
            self._width = min(self.maxwidth, n)
        self._width = max(self.minwidth, n)

    width = property(get_width, set_width)


class ScreenLine:

    def __init__(self, stat=None, text='', attr=0):
        self.stat = stat
        self.text = text
        self.attr = attr

    def format(self, screen, mode):
        if self.stat is None:
            return get_cell(screen.xmax, 'L', self.text)
        return get_line(mode, self.stat)


class StatusBar:

    def __init__(self, width=60, min=0, max=100, status=True):
        self.width = width
        self.curval = min
        self.minval = min
        self.maxval = max
        self.status = status
        self.prepend = '['
        self.append = ']'
        self.usedchar = '|'
        self.freechar = ' '

    def update_cur(self, value):
        value = min(self.maxval, value)
        value = max(self.minval, value)
        self.curval = value

    def update_max(self, value):
        if value >= self.minval:
            self.maxval = value
        else:
            self.maxval = self.minval

    def __str__(self):
        if self.status:
            status = '%d/%d' % (self.curval, self.maxval)

        space = self.width - len(self.prepend) - len(self.append)
        span = self.maxval - self.minval

        if span:
            used = min(float(self.curval) / float(span), 1.0)
        else:
            used = 0.0
        free = 1.0 - used

        # 100% equals full bar width, ignoring status text within the bar
        bar  = self.prepend
        bar += self.usedchar * int(space * used)
        bar += self.freechar * int(space * free)
        if self.status:
            bar  = bar[:(self.width - len(status) - len(self.append))]
            bar += status
        bar += self.append

        return bar

# ------------------------------------------------------------------------- #
#                             DISPLAY FILTERS                               #
# ------------------------------------------------------------------------- #

def human_seconds(numeric):
    for minval, prefix in sorted(PREFIX_TIME.items(), reverse=True):
        if (numeric/minval):
            return '%d%s' % (numeric/minval, prefix)
    return '%ds' % numeric

def human_metric(numeric):
    for minval, prefix in sorted(PREFIX_METRIC.items(), reverse=True):
        if (numeric/minval):
            return '%d%s' % (numeric/minval, prefix)
    return str(numeric)

def human_binary(numeric):
    for minval, prefix in sorted(PREFIX_BINARY.items(), reverse=True):
        if (numeric/minval):
            return '%.2f%s' % (float(numeric)/float(minval), prefix)
    return '%dB' % numeric

def trim(string, length):
    if len(string) <= length:
        return string
    if length == 1:
        return string[0]
    if length > 5:
        return '..%s' % string[-(length-2):]
    return '...'

# ------------------------------------------------------------------------- #
#                             SCREEN LAYOUT                                 #
# ------------------------------------------------------------------------- #

SCREEN_MODES = [
        ScreenMode('HELP'),
        ScreenMode('STATUS'),
        ScreenMode('TRAFFIC'),
        ScreenMode('HTTP'),
        ScreenMode('ERRORS'),
        ScreenMode('CLI'),
]

# Mode: HELP         name            header     xmin    xmax    align
SCREEN_MODES[0].columns = [
        ScreenColumn('help', ' hatop online help ',
                                         SCREEN_XMIN,      0,    'L'),
]

# Mode: STATUS       name            header     xmin    xmax    align
SCREEN_MODES[1].columns = [
        ScreenColumn('svname',       'NAME',      10,     50,    'L'),
        ScreenColumn('weight',       'W',          4,      6,    'R'),
        ScreenColumn('status',       'STATUS',     6,     10,    'L'),
        ScreenColumn('check_status', 'CHECK',      7,     20,    'L'),
        ScreenColumn('act',          'ACT',        3,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('bck',          'BCK',        3,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('qcur',         'QCUR',       5,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('qmax',         'QMAX',       5,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('scur',         'SCUR',       6,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('smax',         'SMAX',       6,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('slim',         'SLIM',       6,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('stot',         'STOT',       6,      0,    'R',
            filters={'ondemand': [human_metric]}),
]

# Mode: TRAFFIC      name            header     xmin    xmax    align
SCREEN_MODES[2].columns = [
        ScreenColumn('svname',       'NAME',      10,     50,    'L'),
        ScreenColumn('weight',       'W',          4,      6,    'R'),
        ScreenColumn('status',       'STATUS',     6,     10,    'L'),
        ScreenColumn('lbtot',        'LBTOT',      8,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('rate',         'RATE',       6,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('rate_lim',     'RLIM',       6,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('rate_max',     'RMAX',       6,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('bin',          'BIN',       12,      0,    'R',
            filters={'always':   [human_binary]}),
        ScreenColumn('bout',         'BOUT',      12,      0,    'R',
            filters={'always':   [human_binary]}),
]

# Mode: HTTP         name            header     xmin    xmax    align
SCREEN_MODES[3].columns = [
        ScreenColumn('svname',       'NAME',      10,     50,    'L'),
        ScreenColumn('weight',       'W',          4,      6,    'R'),
        ScreenColumn('status',       'STATUS',     6,     10,    'L'),
        ScreenColumn('req_rate',     'RATE',       5,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('req_rate_max', 'RMAX',       5,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('req_tot',      'RTOT',       7,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('hrsp_1xx',     '1xx',        5,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('hrsp_2xx',     '2xx',        5,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('hrsp_3xx',     '3xx',        5,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('hrsp_4xx',     '4xx',        5,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('hrsp_5xx',     '5xx',        5,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('hrsp_other',   '?xx',        5,      0,    'R',
            filters={'ondemand': [human_metric]}),
]

# Mode: ERRORS       name            header     xmin    xmax    align
SCREEN_MODES[4].columns = [
        ScreenColumn('svname',       'NAME',      10,     50,    'L'),
        ScreenColumn('weight',       'W',          4,      6,    'R'),
        ScreenColumn('status',       'STATUS',     6,     10,    'L'),
        ScreenColumn('check_status', 'CHECK',      7,     20,    'L'),
        ScreenColumn('chkfail',      'CF',         3,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('chkdown',      'CD',         3,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('lastchg',      'CL',         3,      0,    'R',
            filters={'always':   [human_seconds]}),
        ScreenColumn('econ',         'ECONN',      5,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('ereq',         'EREQ',       5,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('eresp',        'ERSP',       5,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('dreq',         'DREQ',       5,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('dresp',        'DRSP',       5,      0,    'R',
            filters={'ondemand': [human_metric]}),
        ScreenColumn('downtime',     'DOWN',       5,      0,    'R',
            filters={'always':   [human_seconds]}),
]

# Mode: CLI          name            header     xmin    xmax    align
SCREEN_MODES[5].columns = [
        ScreenColumn('cli', ' haproxy command line',
                                         SCREEN_XMIN,      0,    'L'),
]

# ------------------------------------------------------------------------- #
#                                HELPERS                                    #
# ------------------------------------------------------------------------- #

def log(msg):
    sys.stderr.write('%s\n' % msg)

def parse_stat(iterable):
    pxcount = svcount = 0
    pxstat = {} # {iid: {sid: svstat, ...}, ...}

    idx_iid = get_idx('iid')
    idx_sid = get_idx('sid')

    for line in iterable:
        if line.startswith(HAPROXY_STAT_COMMENT):
            continue # comment
        if line.count(HAPROXY_STAT_SEP) != HAPROXY_STAT_NUMFIELDS:
            continue # unknown format

        csv = line.split(HAPROXY_STAT_SEP)

        # Skip parsing but keep counting...
        if svcount > HAPROXY_STAT_MAX_SERVICES:
            iid = int(csv[idx_iid], 10)
            sid = int(csv[idx_sid], 10)
            if iid not in pxstat:
                pxcount += 1
                svcount += 1
            elif sid not in pxstat[iid]:
                svcount += 1
            continue

        svstat = {} # {field: value, ...}

        for idx, field in HAPROXY_STAT_CSV:
            field_type, field_name = field
            value = csv[idx]

            try:
                if field_type is int:
                    if not len(value):
                        value = 0
                    else:
                        value = int(value, 10)
                elif field_type is not type(value):
                        value = field_type(value)
            except ValueError:
                raise RuntimeError('garbage field: %s="%s" (need %s)' % (
                        field_name, value, field_type))

            # Special case
            if field_name == 'status' and value == 'no check':
                value = '-'
            elif field_name == 'check_status' and svstat['status'] == '-':
                value = 'none'

            svstat[field_name] = value

        iid = svstat['iid']
        stype = svstat['type']

        if stype == 0 or stype == 1:  # FRONTEND / BACKEND
            id = svstat['svname']
        else:
            id = svstat['sid']

        try:
            pxstat[iid][id] = svstat
        except KeyError:
            pxstat[iid] = { id: svstat }
            pxcount += 1
        svcount += 1

    return pxstat, pxcount, svcount

def parse_info(iterable):
    info = {}
    for line in iterable:
        line = line.strip()
        if not line:
            continue
        for key, regexp in HAPROXY_INFO_RE.iteritems():
            match = regexp.match(line)
            if match:
                info[key] = match.group('value')
                break
    return info

def get_idx(field):
    return filter(lambda x: x[1][1] == field, HAPROXY_STAT_CSV)[0][0]

def get_width(width, xmax, ncols, idx):
    # distribute excess space evenly from left to right
    if xmax > SCREEN_XMIN:
        xdiff = xmax - SCREEN_XMIN
        if xdiff <= ncols:
            if idx < xdiff:
                width += 1
        else:
            if idx < (xdiff - (xdiff / ncols) * ncols):
                width += 1 # compensate rounding
            width = width + xdiff / ncols
    return width

def get_cell(width, align, value):
    s = str(value)
    if align == 'L':
        s = s.ljust(width)
    elif align == 'C':
        s = s.center(width)
    elif align == 'R':
        s = s.rjust(width)
    return s

def get_head(mode):
    columns = []
    for column in mode.columns:
        s = column.header
        s = get_cell(column.width, column.align, s)
        columns.append(s)
    return SPACE.join(columns)

def get_lines(stat):
    screenlines = []

    for iid, svstats in stat.iteritems():
        lines = []

        try:
            frontend = svstats.pop('FRONTEND')
        except KeyError:
            frontend = None
        try:
            backend = svstats.pop('BACKEND')
        except KeyError:
            backend = None

        if frontend:
            lines.append(ScreenLine(stat=frontend))

        for sid, svstat in sorted(svstats.items()):
            lines.append(ScreenLine(stat=svstat))

        if backend:
            lines.append(ScreenLine(stat=backend))

        if not len(lines):
            continue

        pxname = lines[0].stat['pxname']
        screenlines.append(ScreenLine(attr=curses.A_BOLD,
            text='>>> %s' % pxname))
        screenlines += lines
        screenlines.append(ScreenLine())

    return screenlines

def get_line(mode, stat):
    cells = []
    for column in mode.columns:
        value = stat[column.name]

        for filter in column.filters['always']:
            value = filter(value)

        if len(str(value)) > column.width:
            for filter in column.filters['ondemand']:
                value = filter(value)

        value = str(value)
        value = trim(value, column.width)
        cells.append(get_cell(column.width, column.align, value))

    return SPACE.join(cells)

# ------------------------------------------------------------------------- #
#                            CURSES HELPERS                                 #
# ------------------------------------------------------------------------- #

def curses_init():
    screen = curses.initscr()
    curses.noecho()
    curses.cbreak()
    curses.curs_set(0)
    try:
        curses.start_color()
        curses.use_default_colors()
    except:
        pass
    return screen

def curses_reset(screen):
    screen.keypad(0)
    curses.echo()
    curses.nocbreak()
    curses.endwin()

def draw_line(screen, ypos, xpos, text=None, attr=curses.A_REVERSE):
    screen.hline(ypos, screen.xmin, SPACE, screen.xmax, attr)
    if text:
        screen.addstr(ypos, xpos, text, attr)

def draw_head(screen):
    draw_line(screen, screen.ymin, screen.xmin)
    attr = curses.A_REVERSE | curses.A_BOLD
    screen.addstr(screen.ymin, screen.xmin,
            time.ctime().rjust(screen.xmax - 1), attr)
    screen.addstr(screen.ymin, screen.xmin + 1,
            'hatop version ' + __version__, attr)

def draw_info(screen, data, sb_conn, sb_pipe):
    screen.addstr(screen.ymin + 2, screen.xmin + 2,
            '%s Version: %s  (released: %s)' % (
                data.info['software_name'],
                data.info['software_version'],
                data.info['software_release'],
            ), curses.A_BOLD)

    screen.addstr(screen.ymin + 2, screen.xmin + 56,
            'PID: %d (proc %d)' % (
                int(data.info['pid'], 10),
                int(data.info['procn'], 10),
            ), curses.A_BOLD)

    node = data.info['node']
    if not node:
        node = 'unknown'

    screen.addstr(screen.ymin + 4, screen.xmin + 2,
            '       Node: %s (uptime %s)' % (
                node,
                data.info['uptime'],
            ))

    screen.addstr(screen.ymin + 6, screen.xmin + 2,
            '      Pipes: %s'  % sb_pipe)
    screen.addstr(screen.ymin + 7, screen.xmin + 2,
            'Connections: %s'  % sb_conn)

    screen.addstr(screen.ymin + 9, screen.xmin + 2,
            'Procs: %3d   Tasks: %5d    Queue: %5d    '
            'Proxies: %3d   Services: %4d' % (
                int(data.info['nproc'], 10),
                int(data.info['tasks'], 10),
                int(data.info['runqueue'], 10),
                data.pxcount,
                data.svcount,
            ))

def draw_cols(screen, mode):
    draw_line(screen, screen.hpos, screen.xmin, get_head(mode),
            curses.A_REVERSE | curses.A_BOLD)

def draw_foot(screen, mode, m, stat=None):
    xpos, ypos, xmax = 0, screen.ymax - 1, screen.xmax
    draw_line(screen, ypos, screen.xmin)
    attr_active = curses.A_BOLD
    attr_inactive = curses.A_BOLD | curses.A_REVERSE

    for idx, mode in enumerate(SCREEN_MODES):
        if idx == 0:
            continue
        if idx == 5 and READ_ONLY:
            continue
        if idx == m:
            attr = attr_active
        else:
            attr = attr_inactive

        s = ' %d-%s ' % (idx, mode.name)
        screen.addstr(ypos, xpos, s, attr)
        xpos += len(s)

    if stat:
        s = '[IID: %d SID: %d] H=HELP Q=QUIT' % (stat['iid'], stat['sid'])
    else:
        s = 'UP/DOWN=SCROLL H=HELP Q=QUIT'
    screen.addstr(ypos, xmax - len(s) - 1, s, attr_inactive)

def draw_stat(screen, mode, data):
    attr_cursor = curses.A_REVERSE
    for idx, line in enumerate(data.lines[screen.vmin:screen.vmax+1]):
        if idx == screen.cpos:
            attr = line.attr | curses.A_REVERSE
        else:
            attr = line.attr
        screen.addstr(screen.smin + idx, screen.xmin,
                line.format(screen, mode), attr)

def draw_help(screen):
    screen.addstr(0, 0, __doc__)

def run_cli(screen):
    pass # TODO

# ------------------------------------------------------------------------- #
#                               MAIN LOOP                                   #
# ------------------------------------------------------------------------- #

def mainloop(screen, socket, interval, mode):
    # Prepare status bars
    sb_conn = StatusBar()
    sb_pipe = StatusBar()

    # Sleep time of each iteration in seconds
    scan = 1.0 / 100.0

    # Query socket and redraw the screen in the given interval
    iterations = interval / scan

    m = mode                    # numeric mode
    mode = SCREEN_MODES[m]      # screen mode
    data = HAProxyData(socket)  # data manager

    help = ScreenPad(screen, 0, screen.xmax - 2, 0, __doc__.count('\n'))

    update = True
    i = 0

    while True:

        if screen.sync_size():
            mode.sync_size(screen) # re-calculate column widths

        if i == 0:
            if update:
                # Update data
                data.update_info()
                data.update_stat()

                # Update status bars
                sb_conn.update_max(int(data.info['maxconn'], 10))
                sb_conn.update_cur(int(data.info['curconn'], 10))
                sb_pipe.update_max(int(data.info['maxpipes'], 10))
                sb_pipe.update_cur(int(data.info['curpipes'], 10))

                # Update screen lines
                if 0 < m < 5:
                    data.update_lines()
            else:
                update = True

            # Update screen
            screen.clear()
            draw_head(screen)
            draw_info(screen, data, sb_conn, sb_pipe)
            draw_cols(screen, mode)
            if 0 < m < 5:
                draw_foot(screen, mode, m, data.lines[screen.vpos].stat)
            else:
                draw_foot(screen, mode, m)

            if m == 0:
                draw_help(help)
            elif m == 5:
                run_cli(screen)
            else:
                draw_stat(screen, mode, data)

            # Mark screens for update
            screen.refresh()
            if m == 0:
                help.refresh()

            # Update physical screens at once (prevents flicker)
            curses.doupdate()

            i = iterations

        c = screen.getch()

        if 0 < c < 256:

            c = chr(c)
            if c in 'qQ':
                raise StopIteration()

            if c != str(m) or (c in 'Hh?' and m != 0):
                if c in 'Hh?':
                    m = 0
                elif c in '1234':
                    m = int(c)
                elif c in '5' and not READ_ONLY:
                    m = 5

                # Force screen update with existing data
                if c in 'Hh?12345':
                    i = 0
                    update = False
                    mode = SCREEN_MODES[m]
                    mode.sync_size(screen)
                    continue

        elif c in [curses.KEY_UP, curses.KEY_DOWN, curses.KEY_PPAGE,
                curses.KEY_NPAGE]:
            if 0 < m < 5:
                if c == curses.KEY_UP:
                    if screen.cpos > screen.cmin:
                        screen.cpos -= 1
                    if screen.cpos == screen.cmin and screen.vmin > 0:
                        screen.vmin -= 1
                elif c == curses.KEY_DOWN:
                    maxvmin = len(data.lines) - screen.cmax - 2
                    if screen.cpos < screen.cmax:
                        screen.cpos += 1
                    if screen.cpos == screen.cmax and screen.vmin < maxvmin:
                        screen.vmin += 1
                elif c == curses.KEY_PPAGE:
                    if screen.cpos > screen.cmin:
                        screen.cpos = max(screen.cmin, screen.cpos - 10)
                    if screen.cpos == screen.cmin and screen.vmin > 0:
                        screen.vmin = max(0, screen.vmin - 10)
                elif c == curses.KEY_NPAGE:
                    maxvmin = len(data.lines) - screen.cmax - 2
                    if screen.cpos < screen.cmax:
                        screen.cpos = min(screen.cmax, screen.cpos + 10)
                    if screen.cpos == screen.cmax and screen.vmin < maxvmin:
                        screen.vmin = min(maxvmin, screen.vmin + 10)
            elif m == 0:
                if c == curses.KEY_UP and help.ypos > 0:
                    help.ypos -= 1
                elif c == curses.KEY_DOWN and help.ypos < help.ymax - screen.cmax:
                    help.ypos += 1
                elif c == curses.KEY_PPAGE and help.ypos > 0:
                    help.ypos = max(help.ymin, help.ypos - 10)
                elif c == curses.KEY_NPAGE and help.ypos < help.ymax - screen.cmax:
                    help.ypos = min(help.ymax - screen.cmax, help.ypos + 10)

            # Force screen update with existing data
            i = 0
            update = False
            continue

        time.sleep(scan)
        i -= 1


if __name__ == '__main__':

    from optparse import OptionParser

    version  = 'hatop version %s' % __version__
    usage    = 'Usage: hatop [options]'

    parser = OptionParser(usage=usage, version=version)

    parser.add_option('-s', '--unix-socket', type='str', dest='socket',
            help='path to the haproxy unix socket (mandatory)')
    parser.add_option('-n', '--read-only', action='store_true', dest='ro',
            help='disable the cli and query for stats only')
    parser.add_option('-i', '--update-interval', type='int', dest='interval',
            help='update interval in seconds (1-30, default: 1)', default=1)
    parser.add_option('-m', '--mode', type='int', dest='mode',
            help='start in specific mode (1-5, default: 1)', default=1)

    opts, args = parser.parse_args()

    if not 0 < opts.interval < 31:
        log('invalid update interval: %d' % opts.interval)
        sys.exit(1)
    if not 0 < opts.mode < 6:
        log('invalid mode: %d' % opts.mode)
        sys.exit(1)
    if opts.ro and opts.mode == 5:
        log('cli not available in read-only mode')
        sys.exit(1)
    if not opts.socket:
        parser.print_help()
        sys.exit(0)
    if not os.access(opts.socket, os.R_OK | os.W_OK):
        log('insufficient permissions for socket path %s' % opts.socket)
        sys.exit(2)

    READ_ONLY = opts.ro

    import signal
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(0))

    from socket import error as SocketError
    from _curses import error as CursesError

    socket = HAProxySocket(opts.socket)
    screen = Screen()

    try:
        socket.connect()
        screen.setup()

        try:
            while True:
                try:
                    mainloop(screen, socket, opts.interval, opts.mode)
                except StopIteration:
                    break
                except KeyboardInterrupt:
                    break
                except CursesError, e:
                    screen.reset()
                    log('curses error: %s, restarting...' % e)
                    time.sleep(1)
                    screen.recover()

        except RuntimeError, e:
            screen.reset()
            log('runtime error: %s' % e)
            sys.exit(1)
        except SocketError, e:
            screen.reset()
            log('socket error: %s' % e)
            sys.exit(2)

    finally:
        screen.reset()
        socket.close()

    sys.exit(0)

# vim: et sw=4 tw=78 fdn=1 fdm=indent
