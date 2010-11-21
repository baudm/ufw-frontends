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

import re

import pyinotify


LOG_FILE = '/var/log/ufw.log'
_re_keyval = re.compile(r'([A-Z]+)=([^ ]*)')
_re_event = re.compile(r'\[UFW ([A-Z ]+)\]')


class EventHandler(pyinotify.ProcessEvent):

    def my_init(self, log, callback):
        self._log = log
        self._callback = callback
        # Seek to near EOF if log file is big enough
        try:
            self._log.seek(-4096, 2)
        except IOError:
            pass
        # Get rid of a possibly incomplete line
        self._log.readline()
        for line in self._log:
            data = self._parse(line)
            if data is not None:
                self._callback(data)

    def _parse(self, data):
        event = _re_event.findall(data)[0]
        # Only show 'LIMIT BLOCK' and 'BLOCK' events
        if 'BLOCK' not in event:
            return
        time = ' '.join(data.split()[:3])
        data = dict(_re_keyval.findall(data))
        iface_in = data['IN']
        iface_out = data['OUT']
        src = data['SRC']
        dst = data['DST']
        proto = data['PROTO']
        sport = data['SPT']
        dport = data['DPT']
        return (time, event, iface_in, iface_out, proto, src, sport, dst, dport)

    def process_IN_MODIFY(self, event):
        line = self._log.readline()
        data = self._parse(line)
        if data is not None:
            self._callback(data)


class Notifier(pyinotify.Notifier):

    def __init__(self, callback):
        self._log = open(LOG_FILE, 'r')
        handler = EventHandler(log=self._log, callback=callback)
        wm = pyinotify.WatchManager()
        wm.add_watch(LOG_FILE, pyinotify.IN_MODIFY)
        pyinotify.Notifier.__init__(self, wm, handler)

    def __del__(self):
        self._log.close()

    def _trigger(self, *args):
        self.read_events()
        self.process_events()
        return True
