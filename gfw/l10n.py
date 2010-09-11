#
# l10n: Localization routines
#
# Copyright (C) 2010  Darwin M. Bautista <djclue917@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os.path
import gettext

import ufw.applications
import ufw.backend
import ufw.backend_iptables
import ufw.common
import ufw.frontend
import ufw.parser
import ufw.util

# For module-wide localization
_t = gettext.translation('ufw-frontends', fallback=True)
_ = _t.gettext


def ufw_localize():
    # Just return if the _() function is already installed
    if hasattr(ufw.common, '_'):
        return
    t = gettext.translation(ufw.common.programName, fallback=True)
    # Manually install the _() function for module-wide l10n
    x = t.gettext
    ufw.applications._ = x
    ufw.backend_iptables._ = x
    ufw.backend._ = x
    ufw.common._ = x
    ufw.frontend._ = x
    ufw.parser._ = x
    ufw.util._ = x
