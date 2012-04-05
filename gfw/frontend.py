#
# frontend.py: Base frontend for ufw
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

import shlex

import ufw.common
import ufw.frontend
from ufw.util import valid_address
from ufw.parser import UFWCommandRule

from gfw.util import ANY_ADDR

# Override the error function used by UFWFrontend
def _error(msg, exit=True):
    raise ufw.common.UFWError(msg)

ufw.frontend.error = _error


class Frontend(ufw.frontend.UFWFrontend, object):

    def __init__(self):
        super(Frontend, self).__init__(False)
        # Compatibility for ufw 0.31
        # This is a better way of handling method renames instead of putting
        # try/except blocks all over the whole application code
        try:
            self.backend.get_default_policy
        except AttributeError:
            self.backend.get_default_policy = self.backend._get_default_policy
        try:
            self.backend._is_enabled
        except AttributeError:
            self.backend._is_enabled = self.backend.is_enabled

    @staticmethod
    def _get_ip_version(rule):
        """Determine IP version of rule.
        Extracted from ufw.parser.UFWCommandRule.parse
        """
        # Determine src type
        if rule.src == ANY_ADDR:
            from_type = 'any'
        else:
            from_type = ('v6' if valid_address(rule.src, '6') else 'v4')
        # Determine dst type
        if rule.dst == ANY_ADDR:
            to_type = 'any'
        else:
            to_type = ('v6' if valid_address(rule.dst, '6') else 'v4')
        # Figure out the type of rule (IPv4, IPv6, or both)
        if from_type == 'any' and to_type == 'any':
            ip_version = 'both'
        elif from_type != 'any' and to_type != 'any' and from_type != to_type:
            err_msg = _("Mixed IP versions for 'from' and 'to'")
            raise ufw.common.UFWError(err_msg)
        elif from_type != 'any':
            ip_version = from_type
        elif to_type != 'any':
            ip_version = to_type
        return ip_version

    def config_ipv6(self, enable):
        conf = ('yes' if enable else 'no')
        self.backend.set_default(self.backend.files['defaults'], 'IPV6', conf)

    def config_ipt_module(self, name, enable):
        try:
            modules = self.backend.defaults['ipt_modules'].split()
        except KeyError:
            modules = []
        if enable and name not in modules:
            modules.append(name)
        elif not enable and name in modules:
            modules.remove(name)
        modules = '"' + ' '.join(modules) + '"'
        self.backend.set_default(self.backend.files['defaults'],
                                 'IPT_MODULES', modules)

    def reload(self):
        """Reload firewall"""
        if self.backend._is_enabled():
            self.set_enabled(False)
            self.set_enabled(True)
            return True
        else:
            return False

    def get_rules(self):
        """Returns a generator of processed rules"""
        app_rules = []
        for i, r in enumerate(self.backend.get_rules()):
            if r.dapp or r.sapp:
                t = r.get_app_tuple()
                if t in app_rules:
                    continue
                else:
                    app_rules.append(t)
            yield (i, r)

    ## Modified version of UFWCommandRule.get_command()
    ## It correctly exports the command string for DENY OUT rules
    @staticmethod
    def _get_command(r):
        '''Get command string for rule'''
        res = r.action

        if (r.dst == "0.0.0.0/0" or r.dst == "::/0") and \
           (r.src == "0.0.0.0/0" or r.src == "::/0") and \
           r.sport == "any" and \
           r.sapp == "" and \
           r.interface_in == "" and \
           r.interface_out == "" and \
           r.dport != "any":
            # Short syntax
            if r.direction == "out":
                res += " %s" % r.direction
            if r.logtype != "":
                res += " %s" % r.logtype
            if r.dapp != "":
                res += " %s" % r.dapp
            else:
                res += " %s" % r.dport
                if r.protocol != "any":
                    res += "/%s" % r.protocol
        else:
            # Full syntax
            if r.interface_in != "":
                res += " in on %s" % r.interface_in
            if r.interface_out != "":
                res += " out on %s" % r.interface_out
            if r.logtype != "":
                res += " %s" % r.logtype

            for i in ['src', 'dst']:
                if i == 'src':
                    loc = r.src
                    port = r.sport
                    app = r.sapp
                    dir = r.direction + " from"
                else:
                    loc = r.dst
                    port = r.dport
                    app = r.dapp
                    dir = r.direction + " to"

                if loc == "0.0.0.0/0" or loc == "::/0":
                    loc = "any"
                if loc == "any" and port == "any" and app == "":
                    pass
                else:
                    res += " %s %s" % (dir, loc)
                    if app != "":
                        res += " app %s" % app
                    elif port != "any":
                        res += " port %s" % port

            # If still haven't added more than action, then we have a very
            # generic rule, so mark it as such.
            if res == r.action:
                res += " to any"

            if r.protocol != "any" and r.dapp == "" and r.sapp == "":
                res += " proto %s" % r.protocol

        return res

    def export_rules(self, path):
        with open(path, 'w') as f:
            f.write('#!/bin/sh\n')
            for i, rule in self.get_rules():
                rule = rule.dup_rule()
                # Enclose app names in quotation marks
                if rule.sapp:
                    rule.sapp = "'" + rule.sapp + "'"
                if rule.dapp:
                    rule.dapp = "'" + rule.dapp + "'"
                cmd = 'ufw ' + self._get_command(rule) + '\n'
                f.write(cmd)

    def import_rules(self, path):
        with open(path, 'r') as f:
            for line in f:
                if not line.startswith('ufw '):
                    continue
                args = shlex.split(line)
                args[0] = 'rule'
                p = UFWCommandRule(args[1])
                pr = p.parse(args)
                self.set_rule(pr.data['rule'], pr.data['iptype'])

    def set_rule(self, rule, ip_version=None):
        """set_rule(rule, ip_version=None)

        Changes:
            * ip_version is optional
            * the recently added rule's position is reset
        """
        if ip_version is None:
            ip_version = self._get_ip_version(rule)
        rule = rule.dup_rule()
        # Fix any inconsistency
        if rule.sapp or rule.dapp:
            rule.set_protocol('any')
            if rule.sapp:
                rule.sport = rule.sapp
            if rule.dapp:
                rule.dport = rule.dapp
        # If trying to insert beyond the end, just set position to 0
        if rule.position and not self.backend.get_rule_by_number(rule.position):
            rule.set_position(0)
        res = super(Frontend, self).set_rule(rule, ip_version)
        # Reset the positions of the recently inserted rule(s)
        if rule.position:
            s = rule.position - 1
            e = rule.position + 1
            for r in self.backend.get_rules()[s:e]:
                r.set_position(0)
        return res

    def update_rule(self, pos, rule):
        self.delete_rule(pos, True)
        if not rule.position:
            rule.set_position(pos)
        self.set_rule(rule)

    def move_rule(self, old, new):
        if old == new:
            return
        rule = self.backend.get_rule_by_number(old).dup_rule()
        self.delete_rule(old, True)
        rule.set_position(new)
        self.set_rule(rule)
