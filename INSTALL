************
Installation
************

HATop is written as a single executable python script file called ``hatop``.

This allows easy distribution and installation.

:Package maintainers:

  Please use "hatop" for the final package and executable name.

  This allows users on different platforms to find it easily.


Requirements
============

**HATop is written in pure Python and has no external dependencies!**

* `Python 2.4 <http://python.org/>`_ or later (no Python 3 support planned yet)
* `HAProxy 1.4 <http://haproxy.1wt.eu/>`_ or later


Installation
============

The installation is simple::

  $ install -m 755 bin/hatop /usr/local/bin

  $ install -m 644 man/hatop.1 /usr/local/share/man/man1
  $ gzip /usr/local/share/man/man1/hatop.1


Permissions
===========

HATop itself can be used by any system user.

The permission to connect to a given HAProxy instance is controlled
by the file permission of the unix socket file.

HATop needs ``read`` and ``write`` access (``chmod +rw``) on the socket file.

The initial socket file permissions can be configured in haproxy.conf using
the ``user``, ``group`` and ``mode`` parameters of the ``stats socket`` option.

