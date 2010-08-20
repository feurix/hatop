# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=3

PYTHON_DEPEND="2:2.4"
PYTHON_USE_WITH="ncurses"

inherit python

DESCRIPTION="Interactive ncurses client for HAProxy"
HOMEPAGE="http://feurix.org/projects/hatop/"
SRC_URI="http://hatop.googlecode.com/files/${P}.tar.gz"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE=""

DEPEND=""
RDEPEND="${DEPEND}"

pkg_setup() {
	python_set_active_version 2
}

src_install() {
	newbin hatop.py hatop
	dodoc CHANGES KEYBINDS LICENSE README
}
