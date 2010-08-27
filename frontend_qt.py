#
# frontend_qt.py: PyQt frontend for ufw
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

import sys

from PyQt4 import QtGui, uic

from ufw.frontend import UFWFrontend
from ufw.common import UFWRule

from i18n import _

UI_FILE = 'ufw-qt.ui'


class QtFrontend(UFWFrontend):

    def __init__(self):
        UFWFrontend.__init__(self, False)
        self.ui = uic.loadUi(UI_FILE)
        self.ui.show()


def main():
    app = QtGui.QApplication(sys.argv)
    ui = QtFrontend()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
