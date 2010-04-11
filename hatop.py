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
__version__   = '0.3.0'

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
HAPROXY_CLI_MAXLINES = 2000

# Screen size
SCREEN_XMIN = 78
SCREEN_YMIN = 20
SCREEN_XMAX = 200
SCREEN_YMAX = 200

# Upper limit of stat lines on the pad
STAT_MAX_LINES = 150


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

    def init(self):

        from socket import socket, AF_UNIX, SOCK_STREAM
        self._socket = socket(AF_UNIX, SOCK_STREAM)

        # Initialize interactive socket connection
        self.connect()
        self.send('prompt')
        self.recv()
        self.send('set timeout cli %d' % HAPROXY_CLI_TIMEOUT)
        self.recv()

    def connect(self):
        self._socket.connect(self.path)

    def close(self):
        try:
            self.send('quit')
        except:
            pass
        try:
            self._socket.close()
        except:
            pass

    def send(self, data):
        self._socket.sendall('%s\n' % data)

    def recv(self):
        lines = []
        chunk = ''
        while not chunk.endswith(HAPROXY_CLI_PROMPT):
            if len(lines) == HAPROXY_CLI_MAXLINES:
                chunk = self._socket.recv(HAPROXY_CLI_BUFSIZE)
                continue
            chunk += self._socket.recv(HAPROXY_CLI_BUFSIZE)
            while len(lines) < HAPROXY_CLI_MAXLINES and '\n' in chunk:
                line, chunk = chunk.split('\n', 1)
                lines.append(line)
        return lines

    def get_stat(self):
        stats = {}
        self.send('show stat')
        for line in self.recv():
            if line.count(HAPROXY_STAT_SEP) != HAPROXY_STAT_NUMFIELDS:
                continue # unknown format
            if line.startswith(HAPROXY_STAT_COMMENT):
                continue # comment

            stat = line.split(HAPROXY_STAT_SEP)
            stat = map(lambda s: s.strip(), stat)
            pxname = stat[0]

            try:
                proxy = stats[pxname]
            except KeyError:
                proxy = HAProxyStat()
                stats[pxname] = proxy
            proxy.record(stat)
        return stats

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
        self.info = self.stat = {}
        self.lines = []

    def update_info(self):
        self.info = self.socket.get_info()

    def update_stat(self):
        self.stat = self.socket.get_stat()

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


class ScreenMode:

    def __init__(self, name):
        self.name = name
        self.xmax = SCREEN_XMIN
        self.ymax = SCREEN_YMIN
        self.ypos = 0
        self.cpos = 0
        self.columns = []

    def sync_size(self, xmax, ymax):
        self.xmax = min(xmax, SCREEN_XMAX)
        self.ymax = min(ymax, SCREEN_YMAX)
        for idx, column in enumerate(self.columns):
            column.width = get_width(column.minwidth, self.xmax,
                    len(self.columns), idx)

    def sync_pos(self, mode):
        mode.ypos, mode.cpos = self.ypos, self.cpos
        return mode


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

    def format(self, mode):
        if self.service is None:
            return get_field(mode.xmax, 'L', self.value)
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

def get_field(width, align, s):
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
        s = get_field(column.width, column.align, s)
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
            if len(lines) == STAT_MAX_LINES: break

        for svname, service in sorted(proxy.services.items()):
            line = ScreenLine()
            line.proxy = proxy
            line.service = service
            lines.append(line)
            if len(lines) == STAT_MAX_LINES: break

        if backend:
            line = ScreenLine()
            line.proxy = proxy
            line.service = backend
            lines.append(line)
            if len(lines) == STAT_MAX_LINES: break

        lines.append(ScreenLine())
        if len(lines) >= STAT_MAX_LINES - 2: break

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
        stat_value = get_field(column.width, column.align, stat_value)
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
    ymax, xmax = screen.getmaxyx()
    screen.hline(ypos, 0, SPACE, xmax, attr)
    if text:
        screen.addstr(ypos, xpos, text, attr)

def draw_head(screen):
    draw_line(screen, 0, 0)
    attr = curses.A_REVERSE | curses.A_BOLD
    screen.addstr(0, 0, ctime().rjust(SCREEN_XMIN), attr)
    screen.addstr(0, 1, 'hatop version ' + __version__, attr)

def draw_info(screen, data, sb_conn, sb_pipe):
    screen.addstr(2, 2,
            '%s Version: %s  (released: %s)' % (
                data.info['software_name'],
                data.info['software_version'],
                data.info['software_release'],
            ), curses.A_BOLD)

    screen.addstr(2, 56, 'PID: %d (proc %d)' % (
                int(data.info['pid'], 10),
                int(data.info['procn'], 10),
            ), curses.A_BOLD)

    screen.addstr(4, 2,  '       Node: %s (uptime %s)' % (
                data.info['node'] if data.info['node'] else 'unknown',
                data.info['uptime'],
            ))

    screen.addstr(6, 2,  '      Pipes: %s'  % sb_pipe)
    screen.addstr(7, 2,  'Connections: %s'  % sb_conn)

    num_proxies = len(data.stat)
    num_services = sum(len(proxy.services) for proxy in
            data.stat.itervalues())

    screen.addstr(9, 2,
            'Procs: %3d   Tasks: %5d    Queue: %5d    '
            'Proxies: %3d   Services: %4d' % (
                int(data.info['nproc'], 10),
                int(data.info['tasks'], 10),
                int(data.info['runqueue'], 10),
                num_proxies,
                num_services,
            ))

def draw_cols(screen, mode):
    draw_line(screen, 11, 0, get_head(mode), curses.A_REVERSE | curses.A_BOLD)

def draw_foot(screen, mode, m):
    xpos, ypos, xmax = 0, mode.ymax - 1, mode.xmax
    draw_line(screen, ypos, 0)
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
    idx_min = mode.ypos
    idx_max = mode.ypos + mode.ymax - 16
    for idx, line in enumerate(data.lines):
        if idx < idx_min:
            continue
        if idx > min(idx_max, STAT_MAX_LINES):
            break
        attr = line.attr | attr_cursor if idx == mode.cpos else line.attr
        screen.addstr(idx, 0, line.format(mode), attr)

def draw_help(screen):
    screen.addstr(0, 0, __doc__)

def run_cli(pad):
    pass # TODO

# ------------------------------------------------------------------------- #
#                               MAIN LOOP                                   #
# ------------------------------------------------------------------------- #

def mainloop(screen, socket, interval, mode):
    # Initialize curses screen
    screen.keypad(1)
    screen.nodelay(1)
    screen.idlok(1)
    screen.move(0, 0)

    # Initialize the scrollable content pad
    ymax, xmax = screen.getmaxyx()
    pad = curses.newpad(STAT_MAX_LINES + 2, SCREEN_XMAX)

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
    cmax = 0                    # max cursor ypos

    update = True
    i = 0
    while 1:
        ymax, xmax = screen.getmaxyx()
        if ymax != mode.ymax or xmax != mode.xmax:
            if xmax < SCREEN_XMIN or ymax < SCREEN_YMIN:
                raise RuntimeError(
                        'Terminal too small, need at least %dx%d' % (
                        SCREEN_XMIN, SCREEN_YMIN))
            # Save current screen dimensions and re-calculate column widths
            mode.sync_size(xmax, ymax)

        if i == 0:
            if update:
                # Query the socket for new data and parse it
                data.update_info()
                data.update_stat()
                data.update_lines()

                # Update max cursor position
                cmax = min(STAT_MAX_LINES, len(data.lines) - 2)

                # Update status bars
                sb_conn.update_max(int(data.info['maxconn'], 10))
                sb_conn.update_cur(int(data.info['curconn'], 10))
                sb_pipe.update_max(int(data.info['maxpipes'], 10))
                sb_pipe.update_cur(int(data.info['curpipes'], 10))

                # Update virtual screen
                screen.clear()
                draw_head(screen)
                draw_info(screen, data, sb_conn, sb_pipe)
                draw_cols(screen, mode)
                draw_foot(screen, mode, m)
                screen.noutrefresh()
            else:
                update = True

            # Update virtual pad
            pad.clear()

            if m == 0:
                draw_help(pad)
            elif m == 5:
                run_cli(pad)
            else:
                draw_stat(pad, mode, data)

            pad.noutrefresh(mode.ypos, 0, 13, 0, ymax-3, xmax-1)

            # Update physical screen (virtual screen + pad)
            curses.doupdate()

            i = iterations

        c = screen.getch()

        if 0 < c < 256:
            c = chr(c)
            if c in 'qQ':
                raise StopIteration('end of mainloop')
            if c in ' ':
                i = 0
                continue
            if c in 'Hh?':
                i = m = 0
                mode = SCREEN_MODES[m]
                continue
            if c in '1':
                i, m = 0, 1
                mode = mode.sync_pos(SCREEN_MODES[m])
                continue
            if c in '2':
                i, m = 0, 2
                mode = mode.sync_pos(SCREEN_MODES[m])
                continue
            if c in '3':
                i, m = 0, 3
                mode = mode.sync_pos(SCREEN_MODES[m])
                continue
            if c in '4':
                i, m = 0, 4
                mode = mode.sync_pos(SCREEN_MODES[m])
                continue
            if c in '5' and not READ_ONLY:
                i, m = 0, 5
                mode = SCREEN_MODES[m]
                continue
        elif c == curses.KEY_UP and mode.cpos > 0:
            mode.cpos -= 1
            if mode.cpos < mode.ypos:
                mode.ypos -= 1
            i, update = 0, False
            continue
        elif c == curses.KEY_DOWN and mode.cpos < cmax:
            mode.cpos += 1
            if mode.cpos > mode.ypos + ymax - 16:
                mode.ypos += 1
            i, update = 0, False
            continue
        elif c == curses.KEY_PPAGE and mode.cpos > 0:
            mode.cpos = max(0, mode.cpos - 10)
            if mode.cpos < mode.ypos:
                mode.ypos = max(0, mode.cpos)
            i, update = 0, False
            continue
        elif c == curses.KEY_NPAGE and mode.cpos < cmax:
            mode.cpos = min(cmax, mode.cpos + 10)
            if mode.cpos > mode.ypos + ymax - 16:
                mode.ypos = min(cmax - ymax + 16, mode.ypos + 10,
                        STAT_MAX_LINES)
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
        log('insufficient permissions for path %s' % opts.socket)
        sys.exit(2)

    READ_ONLY = opts.ro
    socket = HAProxySocket(opts.socket)

    try:
        screen = curses_init()
    except Exception as e:
        log('curses error while initializing: %s' % e)
        sys.exit(1)

    from socket import error as SocketError
    from _curses import error as CursesError

    import signal
    signal.signal(signal.SIGINT, lambda signum, frame: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(0))

    while True:
        try:
            try:
                socket.init()
                curses.reset_prog_mode()
                mainloop(screen, socket, opts.interval, opts.mode)
            finally:
                curses_reset(screen) # reset early to display errors
        except StopIteration:
            sys.exit(0)
        except RuntimeError as e:
            log('error: %s' % e)
            sys.exit(1)
        except SocketError as e:
            log('socket error: %s' % e)
            sys.exit(3)
        except CursesError as e:
            log('curses error: %s, restarting...' % e)
            sleep(1)
            continue
        except:
            raise
        finally:
            socket.close()

# vim: et sw=4 tw=78 fdn=1 fdm=indent
