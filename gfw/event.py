#
# event.py: Firewall events
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

import pyinotify


LOG_FILE = '/var/log/ufw.log'


class EventHandler(pyinotify.ProcessEvent):

    def my_init(self, callback):
        self._log = open(LOG_FILE, 'r')
        # Seek to the end of the file
        self._log.seek(0, 2)
        self._callback = callback

    def _parse(self, data):
        data = data.split()
        event = data[8].rstrip(']')
        time = ' '.join(data[:3])
        iface_in = data[9].partition('=')[2]
        iface_out = data[10].partition('=')[2]
        if iface_in:
            proto = data[20].partition('=')[2]
            src = data[12].partition('=')[2]
            sport = data[21].partition('=')[2]
            dst = data[13].partition('=')[2]
            dport = data[22].partition('=')[2]
        if iface_out:
            proto = data[19].partition('=')[2]
            src = data[11].partition('=')[2]
            sport = data[20].partition('=')[2]
            dst = data[12].partition('=')[2]
            dport = data[21].partition('=')[2]
        return (time, event, iface_in, iface_out, proto, src, sport, dst, dport)

    def process_IN_MODIFY(self, event):
        line = self._log.readline()
        data = self._parse(line)
        self._callback(data)


def create_notifier(cb):
    handler = EventHandler(callback=cb)
    wm = pyinotify.WatchManager()
    notifier = pyinotify.ThreadedNotifier(wm, handler)
    wm.add_watch(LOG_FILE, pyinotify.IN_MODIFY)
    return notifier
