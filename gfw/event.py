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
        time = ' '.join(data[:3])
        sport = dport = ''
        for i in data[6:]:
            if i in ('AUDIT]', 'ALLOW]', 'BLOCK]'):
                event = i.rstrip(']')
            elif i.startswith('IN='):
                iface_in = i.partition('=')[2]
            elif i.startswith('OUT='):
                iface_out = i.partition('=')[2]
            elif i.startswith('SRC='):
                src = i.partition('=')[2]
            elif i.startswith('DST='):
                dst = i.partition('=')[2]
            elif i.startswith('PROTO='):
                proto = i.partition('=')[2]
            elif i.startswith('SPT='):
                sport = i.partition('=')[2]
            elif i.startswith('DPT='):
                dport = i.partition('=')[2]
        return (time, event, iface_in, iface_out, proto, src, sport, dst, dport)

    def process_IN_MODIFY(self, event):
        line = self._log.readline()
        data = self._parse(line)
        self._callback(data)


class Notifier(pyinotify.Notifier):

    def __init__(self, callback):
        handler = EventHandler(callback=callback)
        wm = pyinotify.WatchManager()
        wm.add_watch(LOG_FILE, pyinotify.IN_MODIFY)
        pyinotify.Notifier.__init__(self, wm, handler)

    def _trigger(self, *args):
        self.read_events()
        self.process_events()
        return True
