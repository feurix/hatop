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
__version__   = '0.3.2'

import os
import sys
import re
import curses

from time import sleep, ctime

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
SCREEN_YPOS = 11

# Upper limit of parsed service stats
STAT_MAX_SERVICES = 100


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

HAPROXY_STAT_CSV = (
# Note: Fields must be listed in correct order, as described in:
# http://haproxy.1wt.eu/download/1.4/doc/configuration.txt [9.1]

# Field        Type / Prefix   Description

('pxname',         'string'),  # proxy name
('svname',         'string'),  # service name
                               # (FRONTEND / BACKEND / name or server name)
('qcur',           'metric'),  # current queued requests
('qmax',           'metric'),  # max queued requests
('scur',           'metric'),  # current sessions
('smax',           'metric'),  # max sessions
('slim',           'metric'),  # sessions limit
('stot',           'metric'),  # total sessions
('bin',            'binary'),  # bytes in
('bout',           'binary'),  # bytes out
('dreq',           'metric'),  # denied requests
('dresp',          'metric'),  # denied responses
('ereq',           'metric'),  # request errors
('econ',           'metric'),  # connection errors
('eresp',          'metric'),  # response errors (among which srv_abrt)
('wretr',          'metric'),  # retries (warning)
('wredis',         'metric'),  # redispatches (warning)
('status',         'metric'),  # status (UP/DOWN/NOLB/MAINT/MAINT(via)...)
('weight',         'metric'),  # server weight (server),
                               # total weight (backend)
('act',            'metric'),  # server is active (server),
                               # number of active servers (backend)
('bck',            'metric'),  # server is backup (server),
                               # number of backup servers (backend)
('chkfail',        'metric'),  # number of failed checks
('chkdown',        'metric'),  # number of UP->DOWN transitions
('lastchg',        'seconds'), # last status change (in seconds)
('downtime',       'seconds'), # total downtime (in seconds)
('qlimit',         'metric'),  # queue limit
('pid',            'metric'),  # process id
('iid',            'metric'),  # unique proxy id
('sid',            'metric'),  # service id (unique inside a proxy)
('throttle',       'metric'),  # warm up status
('lbtot',          'metric'),  # total number of times a server was selected
('tracked',        'metric'),  # id of proxy/server if tracking is enabled
('type',           'metric'),  # (0=frontend, 1=backend, 2=server, 3=socket)
('rate',           'metric'),  # number of sessions per second over last
                               # elapsed second
('rate_lim',       'metric'),  # limit on new sessions per second
('rate_max',       'metric'),  # max number of new sessions per second
('check_status',   'string'),  # status of last health check, one of:
                               #   UNK     -> unknown
                               #   INI     -> initializing
                               #   SOCKERR -> socket error
                               #   L4OK    -> check passed on layer 4,
                               #              no upper layers testing enabled
                               #   L4TMOUT -> layer 1-4 timeout
                               #   L4CON   -> layer 1-4 connection problem,
                               #              for example:
                               #              "Connection refused" (tcp rst)
                               #              "No route to host" (icmp)
                               #   L6OK    -> check passed on layer 6
                               #   L6TOUT  -> layer 6 (SSL) timeout
                               #   L6RSP   -> layer 6 invalid response,
                               #              protocol error
                               #   L7OK    -> check passed on layer 7
                               #   L7OKC   -> check conditionally passed on
                               #              layer 7, for example 404 with
                               #              disable-on-404
                               #   L7TOUT  -> layer 7 (HTTP/SMTP) timeout
                               #   L7RSP   -> layer 7 invalid response,
                               #              protocol error
                               #   L7STS   -> layer 7 response error,
                               #              for example HTTP 5xx
('check_code',     'metric'),  # layer5-7 code, if available
('check_duration', 'metric'),  # time in ms took to finish last health check
('hrsp_1xx',       'metric'),  # http responses with 1xx code
('hrsp_2xx',       'metric'),  # http responses with 2xx code
('hrsp_3xx',       'metric'),  # http responses with 3xx code
('hrsp_4xx',       'metric'),  # http responses with 4xx code
('hrsp_5xx',       'metric'),  # http responses with 5xx code
('hrsp_other',     'metric'),  # http responses with other codes
                               # (protocol error)
('hanafail',       'string'),  # failed health checks details
('req_rate',       'metric'),  # HTTP requests per second
('req_rate_max',   'metric'),  # max number of HTTP requests per second
('req_tot',        'metric'),  # total number of HTTP requests received
('cli_abrt',       'metric'),  # number of data transfers aborted by client
('srv_abrt',       'metric'),  # number of data transfers aborted by server
)
HAPROXY_STAT_NUMFIELDS = len(HAPROXY_STAT_CSV)
HAPROXY_STAT_COMMENT = '#'
HAPROXY_STAT_SEP = ','

# All (possible) big numeric values on the screen are humanized using the
# metric prefix set, while everything byte related is using binary prefixes.
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

    def __enter__(self):
        # Initialize interactive socket connection
        self.connect()
        self.send('prompt')
        self.wait()
        self.send('set timeout cli %d' % HAPROXY_CLI_TIMEOUT)
        self.wait()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def connect(self):
        self._socket.connect(self.path)

    def close(self):
        try:
            self.send('quit')
            self._socket.close()
        except:
            pass

    def send(self, cmdline):
        self._socket.sendall('%s\n' % cmdline)

    def wait(self):
        # Wait for the prompt and discard data.
        chunk = ''
        while not chunk.endswith(HAPROXY_CLI_PROMPT):
            chunk = chunk[-(len(HAPROXY_CLI_PROMPT)-1):] + \
                    self._socket.recv(HAPROXY_CLI_BUFSIZE)

    def recv(self):
        # Receive lines until HAPROXY_CLI_MAXLINES or the prompt is reached.
        # If the prompt was not found, discard data and wait for it.
        linecount = 0
        chunk = ''
        while not chunk.endswith(HAPROXY_CLI_PROMPT):
            if linecount == HAPROXY_CLI_MAXLINES:
                chunk = chunk[-(len(HAPROXY_CLI_PROMPT)-1):] + \
                        self._socket.recv(HAPROXY_CLI_BUFSIZE)
                continue
            chunk += self._socket.recv(HAPROXY_CLI_BUFSIZE)
            while linecount < HAPROXY_CLI_MAXLINES and '\n' in chunk:
                line, chunk = chunk.split('\n', 1)
                linecount += 1
                yield line

    def get_stat(self):
        stats, overflow = {}, []
        pxcount = svcount = 0
        self.send('show stat')
        for line in self.recv():
            if line.count(HAPROXY_STAT_SEP) != HAPROXY_STAT_NUMFIELDS:
                continue # unknown format
            if line.startswith(HAPROXY_STAT_COMMENT):
                continue # comment

            if svcount < STAT_MAX_SERVICES:
                stat = line.split(HAPROXY_STAT_SEP)
            else:
                stat = line.split(HAPROXY_STAT_SEP, 1)

            stat = map(lambda s: s.strip(), stat)
            pxname = stat[0]

            try:
                proxy = stats[pxname]
            except KeyError:
                if svcount < STAT_MAX_SERVICES:
                    proxy = HAProxyStat()
                    stats[pxname] = proxy
                    pxcount += 1
                elif pxname not in overflow:
                    overflow.append(pxname)
                    pxcount += 1

            if svcount < STAT_MAX_SERVICES:
                proxy.record(stat)
            svcount += 1

        return stats, pxcount, svcount

    def get_info(self):
        info = {}
        self.send('show info')
        for line in self.recv():
            line = line.strip()
            if not line:
                continue
            for key, regexp in HAPROXY_INFO_RE.iteritems():
                match = regexp.match(line)
                if match:
                    info[key] = match.group('value')
                    break
        return info


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


class HAProxyStat:

    def __init__(self):
        self.services = {}

    def record(self, stat):
        svname = stat[1]
        try:
            service = self.services[svname]
        except KeyError:
            service = HAProxyServiceStat(self)
            self.services[svname] = service

        for idx, field in enumerate(HAPROXY_STAT_CSV):
            name, type = field
            value = stat[idx]

            # Special case
            if name == 'status' and value == 'no check':
                value = '-'
            elif name == 'check_status' and service.status[1] == '-':
                value = 'none'

            setattr(service, name, (type, value))


class HAProxyServiceStat:

    def __init__(self, proxy):
        self.proxy = proxy

class Screen:

    def __init__(self):
        self.screen = None
        self.xmin = 0
        self.xmax = SCREEN_XMIN
        self.ymin = 0
        self.ymax = SCREEN_YMIN
        self.vmin = 0
        self.cmin = 0
        self.cpos = 0
        self.hpos = SCREEN_YPOS
        self.init()

    def init(self):
        self.screen = curses_init()
        self.screen.keypad(1)
        self.screen.nodelay(1)
        self.screen.idlok(1)
        self.screen.move(0, 0)

    def reset(self):
        curses_reset(self.screen)

    def refresh(self):
        self.screen.noutrefresh()

    def clear_all(self):
        self.screen.erase()

    def clear_stat(self):
        self.screen.redrawln(self.smin, self.cmax)

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
            raise RuntimeError('Screen too small, need at least %dx%d' % (
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

    def __init__(self, name, header, minwidth, maxwidth, align):
        self.name = name
        self.header = header
        self.align = align
        self.minwidth = minwidth
        self.maxwidth = maxwidth
        self.width = minwidth

    def __eq__(self, name):
        return True if name == self.name else False

    @property
    def width(self):
        return self._width

    @width.setter
    def width(self, n):
        if self.maxwidth:
            self._width = min(self.maxwidth, n)
        self._width = max(self.minwidth, n)


class ScreenLine:

    def __init__(self):
        self.proxy = None
        self.service = None
        self.value = ''
        self.attr = 0

    def format(self, screen, mode):
        if self.service is None:
            return get_cell(screen.xmax, 'L', self.value)
        return get_line(mode, self.service)


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
        self.maxval = value if value >= self.minval else self.minval

    def __str__(self):
        if self.status:
            status = '%d/%d' % (self.curval, self.maxval)

        space = self.width - len(self.prepend) - len(self.append)
        span = self.maxval - self.minval

        used = min(float(self.curval) / float(span), 1.0) if span else 0.0
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
        ScreenColumn('act',          'ACT',        3,      0,    'R'),
        ScreenColumn('bck',          'BCK',        3,      0,    'R'),
        ScreenColumn('qcur',         'QCUR',       5,      0,    'R'),
        ScreenColumn('qmax',         'QMAX',       5,      0,    'R'),
        ScreenColumn('scur',         'SCUR',       6,      0,    'R'),
        ScreenColumn('smax',         'SMAX',       6,      0,    'R'),
        ScreenColumn('slim',         'SLIM',       6,      0,    'R'),
        ScreenColumn('stot',         'STOT',       6,      0,    'R'),
]

# Mode: TRAFFIC      name            header     xmin    xmax    align
SCREEN_MODES[2].columns = [
        ScreenColumn('svname',       'NAME',      10,     50,    'L'),
        ScreenColumn('weight',       'W',          4,      6,    'R'),
        ScreenColumn('status',       'STATUS',     6,     10,    'L'),
        ScreenColumn('lbtot',        'LBTOT',      8,      0,    'R'),
        ScreenColumn('rate',         'RATE',       6,      0,    'R'),
        ScreenColumn('rate_lim',     'RLIM',       6,      0,    'R'),
        ScreenColumn('rate_max',     'RMAX',       6,      0,    'R'),
        ScreenColumn('bin',          'BIN',       12,      0,    'R'),
        ScreenColumn('bout',         'BOUT',      12,      0,    'R'),
]

# Mode: HTTP         name            header     xmin    xmax    align
SCREEN_MODES[3].columns = [
        ScreenColumn('svname',       'NAME',      10,     50,    'L'),
        ScreenColumn('weight',       'W',          4,      6,    'R'),
        ScreenColumn('status',       'STATUS',     6,     10,    'L'),
        ScreenColumn('req_rate',     'RATE',       5,      0,    'R'),
        ScreenColumn('req_rate_max', 'RMAX',       5,      0,    'R'),
        ScreenColumn('req_tot',      'RTOT',       7,      0,    'R'),
        ScreenColumn('hrsp_1xx',     '1xx',        5,      0,    'R'),
        ScreenColumn('hrsp_2xx',     '2xx',        5,      0,    'R'),
        ScreenColumn('hrsp_3xx',     '3xx',        5,      0,    'R'),
        ScreenColumn('hrsp_4xx',     '4xx',        5,      0,    'R'),
        ScreenColumn('hrsp_5xx',     '5xx',        5,      0,    'R'),
        ScreenColumn('hrsp_other',   '?xx',        5,      0,    'R'),
]

# Mode: ERRORS       name            header     xmin    xmax    align
SCREEN_MODES[4].columns = [
        ScreenColumn('svname',       'NAME',      10,     50,    'L'),
        ScreenColumn('weight',       'W',          4,      6,    'R'),
        ScreenColumn('status',       'STATUS',     6,     10,    'L'),
        ScreenColumn('check_status', 'CHECK',      7,     20,    'L'),
        ScreenColumn('chkfail',      'CF',         3,      0,    'R'),
        ScreenColumn('chkdown',      'CD',         3,      0,    'R'),
        ScreenColumn('lastchg',      'CL',         3,      0,    'R'),
        ScreenColumn('econ',         'ECONN',      5,      0,    'R'),
        ScreenColumn('ereq',         'EREQ',       5,      0,    'R'),
        ScreenColumn('eresp',        'ERSP',       5,      0,    'R'),
        ScreenColumn('dreq',         'DREQ',       5,      0,    'R'),
        ScreenColumn('dresp',        'DRSP',       5,      0,    'R'),
        ScreenColumn('downtime',     'DOWN',       5,      0,    'R'),
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

def human_time(seconds):
    value = int(seconds, 10)
    for minval, prefix in sorted(PREFIX_TIME.items(), reverse=True):
        if (value/minval):
            return '%d%s' % (value/minval, prefix)
    return '%ss' % value

def human_numeric(numval, si=True):
    value = int(numval, 10)
    P = PREFIX_METRIC if si else PREFIX_BINARY
    for minval, prefix in sorted(P.items(), reverse=True):
        if (value/minval):
            return '%.1f%s' % (float(value)/minval, prefix)
    return str(value)

def trim(l, s):
    if len(s) <= l:
        return s
    if l == 1:
        return s[0]
    if l > 5:
        return '..%s' % s[-(l-2):]
    return '...'

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

def get_cell(width, align, s):
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
    lines = []
    for pxname, proxy in sorted(stat.items()):
        line = ScreenLine()
        line.proxy = proxy
        line.value = '>>> %s' % pxname
        line.attr = curses.A_BOLD
        lines.append(line)

        try:
            frontend = proxy.services.pop('FRONTEND')
        except:
            frontend = None
        try:
            backend = proxy.services.pop('BACKEND')
        except:
            backend = None

        if frontend:
            line = ScreenLine()
            line.proxy = proxy
            line.service = frontend
            lines.append(line)

        for svname, service in sorted(proxy.services.items()):
            line = ScreenLine()
            line.proxy = proxy
            line.service = service
            lines.append(line)

        if backend:
            line = ScreenLine()
            line.proxy = proxy
            line.service = backend
            lines.append(line)

        lines.append(ScreenLine())

    return lines

def get_line(mode, service):
    columns = []
    for column in mode.columns:
        stat_type, stat_value = getattr(service, column.name)
        if len(stat_value):
            if stat_type == 'metric' and len(stat_value) > column.width:
                stat_value = human_numeric(stat_value, si=True)
            elif stat_type == 'binary':
                stat_value = human_numeric(stat_value, si=False)
            elif stat_type == 'seconds':
                stat_value = human_time(stat_value)
            stat_value = trim(column.width, stat_value)
        stat_value = get_cell(column.width, column.align, stat_value)
        columns.append(stat_value)
    return SPACE.join(columns)

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
    curses.def_prog_mode() # save state for recovery
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
            ctime().rjust(screen.xmax - 1), attr)
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

    screen.addstr(screen.ymin + 4, screen.xmin + 2,
            '       Node: %s (uptime %s)' % (
                data.info['node'] if data.info['node'] else 'unknown',
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

def draw_foot(screen, mode, m):
    xpos, ypos, xmax = 0, screen.ymax - 1, screen.xmax
    draw_line(screen, ypos, screen.xmin)
    attr_active = curses.A_BOLD
    attr_inactive = curses.A_BOLD | curses.A_REVERSE

    for idx, mode in enumerate(SCREEN_MODES):
        if idx == 0:
            continue
        if idx == 5 and READ_ONLY:
            continue
        attr = attr_active if idx == m else attr_inactive
        s = ' %d-%s ' % (idx, mode.name)
        screen.addstr(ypos, xpos, s, attr)
        xpos += len(s)

    s = 'UP/DOWN=SCROLL H=HELP Q=QUIT'
    screen.addstr(ypos, xmax - len(s) - 1, s, attr_inactive)

def draw_stat(screen, mode, data):
    attr_cursor = curses.A_REVERSE
    for idx, line in enumerate(data.lines[screen.vmin:screen.vmax+1]):
        attr = line.attr | attr_cursor if idx == screen.cpos else line.attr
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

                # Update screen lines
                if 0 < m < 5:
                    data.update_lines()

                # Update status bars
                sb_conn.update_max(int(data.info['maxconn'], 10))
                sb_conn.update_cur(int(data.info['curconn'], 10))
                sb_pipe.update_max(int(data.info['maxpipes'], 10))
                sb_pipe.update_cur(int(data.info['curpipes'], 10))

                # Update the whole screen
                screen.clear_all()
                draw_head(screen)
                draw_info(screen, data, sb_conn, sb_pipe)
                draw_cols(screen, mode)
                draw_foot(screen, mode, m)
            else:
                # Redraw the stat display with current data
                if 0 < m < 5:
                    screen.clear_stat()
                update = True

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

            # Update physical screens
            curses.doupdate()

            i = iterations

        c = screen.getch()

        if 0 < c < 256:
            c = chr(c)
            if c in 'qQ':
                raise StopIteration()
            if c in ' ':
                i = 0
                continue
            if c in 'Hh?':
                i = m = 0
                mode = SCREEN_MODES[m]
                mode.sync_size(screen)
                continue
            if c in '1':
                i, m = 0, 1
                mode = SCREEN_MODES[m]
                mode.sync_size(screen)
                continue
            if c in '2':
                i, m = 0, 2
                mode = SCREEN_MODES[m]
                mode.sync_size(screen)
                continue
            if c in '3':
                i, m = 0, 3
                mode = SCREEN_MODES[m]
                mode.sync_size(screen)
                continue
            if c in '4':
                i, m = 0, 4
                mode = SCREEN_MODES[m]
                mode.sync_size(screen)
                continue
            if c in '5' and not READ_ONLY:
                i, m = 0, 5
                mode = SCREEN_MODES[m]
                mode.sync_size(screen)
                continue

        if 0 < m < 5:
            if c == curses.KEY_UP:
                if screen.cpos > screen.cmin:
                    screen.cpos -= 1
                if screen.cpos == screen.cmin and screen.vmin > 0:
                    screen.vmin -= 1
                i, update = 0, False
                continue
            if c == curses.KEY_DOWN:
                maxvmin = len(data.lines) - screen.cmax - 2
                if screen.cpos < screen.cmax:
                    screen.cpos += 1
                if screen.cpos == screen.cmax and screen.vmin < maxvmin:
                    screen.vmin += 1
                i, update = 0, False
                continue
            if c == curses.KEY_PPAGE:
                if screen.cpos > screen.cmin:
                    screen.cpos = max(screen.cmin, screen.cpos - 10)
                if screen.cpos == screen.cmin and screen.vmin > 0:
                    screen.vmin = max(0, screen.vmin - 10)
                i, update = 0, False
                continue
            if c == curses.KEY_NPAGE:
                maxvmin = len(data.lines) - screen.cmax - 2
                if screen.cpos < screen.cmax:
                    screen.cpos = min(screen.cmax, screen.cpos + 10)
                if screen.cpos == screen.cmax and screen.vmin < maxvmin:
                    screen.vmin = min(maxvmin, screen.vmin + 10)
                i, update = 0, False
                continue
        elif m == 0:
            if c == curses.KEY_UP and help.ypos > 0:
                help.ypos -= 1
                i, update = 0, False
                continue
            if c == curses.KEY_DOWN and help.ypos < help.ymax - screen.cmax:
                help.ypos += 1
                i, update = 0, False
                continue
            if c == curses.KEY_PPAGE and help.ypos > 0:
                help.ypos = max(help.ymin, help.ypos - 10)
                i, update = 0, False
                continue
            if c == curses.KEY_NPAGE and help.ypos < help.ymax - screen.cmax:
                help.ypos = min(help.ymax - screen.cmax, help.ypos + 10)
                i, update = 0, False
                continue

        sleep(scan)
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

    try:
        screen = Screen()
    except Exception as e:
        log('error while initializing screen: %s' % e)
        sys.exit(1)

    import signal
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(0))

    from socket import error as SocketError
    from _curses import error as CursesError

    try:
        with HAProxySocket(opts.socket) as socket:

            while True:
                try:
                    curses.reset_prog_mode()
                    mainloop(screen, socket, opts.interval, opts.mode)
                except StopIteration:
                    break
                except KeyboardInterrupt:
                    break
                except CursesError as e:
                    screen.reset()
                    log('curses error: %s, restarting...' % e)
                    sleep(1)

    except RuntimeError as e:
        screen.reset()
        log('runtime error: %s' % e)
        sys.exit(1)
    except SocketError as e:
        screen.reset()
        log('socket error: %s' % e)
        sys.exit(2)
    finally:
        screen.reset()

    sys.exit(0)

# vim: et sw=4 tw=78 fdn=1 fdm=indent
