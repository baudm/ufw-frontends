#
# frontend_gtk.py: PyGTK frontend for ufw
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

import gtk

from ufw.common import UFWRule

from ufwfe.frontend import Frontend
from ufwfe.i18n import _
from ufwfe.util import get_ui_path, get_formatted_rule
from ufwfe.util import ANY_ADDR, ANY_PORT


class GtkFrontend(Frontend):

    UI_FILE = 'ufw-gtk.glade'

    def __init__(self):
        Frontend.__init__(self)
        self.ui = gtk.Builder()
        path = get_ui_path(self.UI_FILE)
        self.ui.add_from_file(path)
        # models
        self.rules_model = self.ui.get_object('rules_model')
        self._update_rules_model()
        self._update_apps_model()
        # dialogs
        self.rule_dialog = self.ui.get_object('rule_dialog')
        self.prefs_dialog = self.ui.get_object('prefs_dialog')
        self.about_dialog = self.ui.get_object('about_dialog')
        self._init_dialogs()
        self._init_main_window()
        # connect signals and show main window
        self.ui.connect_signals(self)
        main_window = self.ui.get_object('main_window')
        main_window.show_all()

    def _init_main_window(self):
        # enable multiple selections
        self.selection = self.ui.get_object('rules_view').get_selection()
        self.selection.set_mode(gtk.SELECTION_MULTIPLE)
        # set initial state of toggle button
        toggle = self.ui.get_object('toggle_firewall')
        if not self.backend._is_enabled():
            toggle.set_label(_('Enable Firewall'))
            toggle.set_active(False)
            img = self.ui.get_object('play')
        else:
            toggle.set_label(_('Disable Firewall'))
            toggle.set_active(True)
            img = self.ui.get_object('stop')
        toggle.set_image(img)

    def _init_dialogs(self):
        main_window = self.ui.get_object('main_window')
        for name in ('rule_dialog', 'prefs_dialog', 'about_dialog'):
            self.ui.get_object(name).set_transient_for(main_window)
        self._init_prefs_dialog()

    def _init_prefs_dialog(self):
        # comboboxes
        logging_opts = map(str.lower, self._get_cbox_values('logging_cbox'))
        policy_opts = map(str.lower, self._get_cbox_values('incoming_policy_cbox'))
        logging = logging_opts.index(self.backend.defaults['loglevel'])
        default_incoming = policy_opts.index(self.backend.get_default_policy('input'))
        default_outgoing = policy_opts.index(self.backend.get_default_policy('output'))
        defaults = {
            'logging_cbox': logging,
            'incoming_policy_cbox': default_incoming,
            'outgoing_policy_cbox': default_outgoing
        }
        for name, default in defaults.iteritems():
            cbox = self.ui.get_object(name)
            cbox.set_active(default)
        # checkbox
        cb = self.ui.get_object('enable_ipv6')
        conf = self.backend.defaults['ipv6']
        cb.set_active(conf == 'yes')

    def _get_cbox_values(self, name):
        ls = self.ui.get_object(name).get_model()
        values = []
        for v in ls:
            values.append(v[0])
        return values

    def _get_combobox_value(self, name):
        combobox = self.ui.get_object(name)
        model = combobox.get_model()
        active = combobox.get_active()
        if active >= 0:
            return model[active][0]

    def _set_combobox_value(self, name, value):
        values = map(str.lower, self._get_cbox_values(name))
        i = values.index(value.lower())
        cbox = self.ui.get_object(name)
        cbox.set_active(i)

    def _update_rules_model(self):
        rules_model = self.ui.get_object('rules_model')
        rules_model.clear()
        for row in self.get_rules():
            idx, rule_num, r = row
            r = get_formatted_rule(r)
            row = [rule_num, r.action, r.direction, r.protocol, r.src, r.sport, r.dst, r.dport, idx]
            rules_model.append(row)

    def _update_apps_model(self):
        apps_model = self.ui.get_object('apps_model')
        apps_model.clear()
        apps = self.backend.profiles.keys()
        apps.sort()
        for app in apps:
            apps_model.append([app])

    def _get_rule_from_dialog(self):
        action = self._get_combobox_value('action_cbox').lower()
        protocol = self._get_combobox_value('protocol_cbox').lower()
        rule = UFWRule(action, protocol)
        # direction
        in_rbutton = self.ui.get_object('in_rbutton')
        direction = ('in' if in_rbutton.get_active() else 'out')
        rule.set_direction(direction)
        # logtype
        log_map = {'Off': '', 'New Connections': 'log', 'Packets': 'log-all'}
        logtype = log_map[self._get_combobox_value('rule_logging_cbox')]
        rule.set_logtype(logtype)
        # src
        if self.ui.get_object('src_addr_custom_rbutton').get_active():
            addr = self.ui.get_object('src_addr_custom_entry').get_text()
            rule.set_src(addr)
        # src port
        port = ANY_PORT
        if self.ui.get_object('src_port_custom_rbutton').get_active():
            port = self.ui.get_object('src_port_custom_entry').get_text()
        elif self.ui.get_object('src_app_rbutton').get_active():
            port = self._get_combobox_value('src_app_cbox')
            rule.sapp = port
        rule.set_port(port, 'src')
        # dst
        if self.ui.get_object('dst_addr_custom_rbutton').get_active():
            addr = self.ui.get_object('dst_addr_custom_entry').get_text()
            rule.set_dst(addr)
        # dst port
        port = ANY_PORT
        if self.ui.get_object('dst_port_custom_rbutton').get_active():
            port = self.ui.get_object('dst_port_custom_entry').get_text()
        elif self.ui.get_object('dst_app_rbutton').get_active():
            port = self._get_combobox_value('dst_app_cbox')
            rule.dapp = port
        rule.set_port(port, 'dst')
        return rule

    def _set_rule_to_dialog(self, rule):
        # action
        self._set_combobox_value('action_cbox', rule.action)
        # direction
        in_rbutton = self.ui.get_object('in_rbutton')
        in_rbutton.set_active(rule.direction == 'in')
        # protocol
        self._set_combobox_value('protocol_cbox', rule.protocol)
        # logging
        log_rmap = {'': 'Off', 'log': 'New Connections', 'log-all': 'Packets'}
        logtype = log_rmap[rule.logtype]
        self._set_combobox_value('rule_logging_cbox', logtype)
        # src
        if rule.src == ANY_ADDR:
            self.ui.get_object('src_addr_any_rbutton').set_active(True)
            addr = ''
        else:
            self.ui.get_object('src_addr_custom_rbutton').set_active(True)
            addr = rule.src
        self.ui.get_object('src_addr_custom_entry').set_text(addr)
        # src port
        if rule.sapp:
            self.ui.get_object('src_app_rbutton').set_active(True)
            self._set_combobox_value('src_app_cbox', rule.sapp)
        elif rule.sport == ANY_PORT:
            self.ui.get_object('src_port_any_rbutton').set_active(True)
        else:
            self.ui.get_object('src_port_custom_rbutton').set_active(True)
            self.ui.get_object('src_port_custom_entry').set_text(rule.sport)
        # dst
        if rule.dst == ANY_ADDR:
            self.ui.get_object('dst_addr_any_rbutton').set_active(True)
            addr = ''
        else:
            self.ui.get_object('dst_addr_custom_rbutton').set_active(True)
            addr = rule.dst
        self.ui.get_object('dst_addr_custom_entry').set_text(addr)
        # src port
        if rule.dapp:
            self.ui.get_object('dst_app_rbutton').set_active(True)
            self._set_combobox_value('dst_app_cbox', rule.dapp)
        elif rule.dport == ANY_PORT:
            self.ui.get_object('dst_port_any_rbutton').set_active(True)
        else:
            self.ui.get_object('dst_port_custom_rbutton').set_active(True)
            self.ui.get_object('dst_port_custom_entry').set_text(rule.dport)

    def on_src_addr_custom_rbutton_toggled(self, widget):
        entry = self.ui.get_object('src_addr_custom_entry')
        entry.set_sensitive(widget.get_active())

    def on_dst_addr_custom_rbutton_toggled(self, widget):
        entry = self.ui.get_object('dst_addr_custom_entry')
        entry.set_sensitive(widget.get_active())

    def on_src_port_custom_rbutton_toggled(self, widget):
        cboxentry = self.ui.get_object('src_port_custom_entry')
        cboxentry.set_sensitive(widget.get_active())

    def on_dst_port_custom_rbutton_toggled(self, widget):
        cboxentry = self.ui.get_object('dst_port_custom_entry')
        cboxentry.set_sensitive(widget.get_active())

    def on_src_app_rbutton_toggled(self, widget):
        app_cbox = self.ui.get_object('src_app_cbox')
        app_cbox.set_sensitive(widget.get_active())
        app_rbutton = self.ui.get_object('dst_app_rbutton')
        protocol_cbox = self.ui.get_object('protocol_cbox')
        protocol_cbox.set_sensitive(not widget.get_active() and not app_rbutton.get_active())

    def on_dst_app_rbutton_toggled(self, widget):
        app_cbox = self.ui.get_object('dst_app_cbox')
        app_cbox.set_sensitive(widget.get_active())
        app_rbutton = self.ui.get_object('src_app_rbutton')
        protocol_cbox = self.ui.get_object('protocol_cbox')
        protocol_cbox.set_sensitive(not widget.get_active() and not app_rbutton.get_active())

    def on_toggle_firewall_toggled(self, widget):
        if self.backend._is_enabled():
            print self.set_enabled(False)
            img = self.ui.get_object('play')
            widget.set_image(img)
            widget.set_label(_('Enable Firewall'))
        else:
            print self.set_enabled(True)
            img = self.ui.get_object('stop')
            widget.set_image(img)
            widget.set_label(_('Disable Firewall'))

    def on_reload_firewall_clicked(self, widget):
        if self.reload():
            self._update_rules_model()

    def on_insert_rule_clicked(self, widget):
        if self.backend._is_enabled():
            if self.rule_dialog.run():
                rule = self._get_rule_from_dialog()
                self.set_rule(rule)
                self._update_rules_model()
            self.rule_dialog.hide()

    def on_delete_rule_clicked(self, widget):
        if self.backend._is_enabled():
            rows = self.selection.get_selected_rows()[1]
            rows.reverse()
            for i in rows:
                self.delete_rule(i[0] + 1, True)
            self._update_rules_model()

    def on_help_menu_activate(self, widget):
        self.about_dialog.run()
        self.about_dialog.hide()

    def on_rules_view_row_activated(self, widget, itr, path):
        rules = self.backend.get_rules()
        i = self.rules_model[itr[0]][8]
        self._set_rule_to_dialog(rules[i])
        if self.rule_dialog.run():
            pos = itr[0] + 1
            self.delete_rule(pos, True)
            # If inserting at the end, position should be 0
            if pos > len(self.rules_model) - 1:
                pos = 0
            rule = self._get_rule_from_dialog()
            rule.set_position(pos)
            self.set_rule(rule)
            self._update_rules_model()
        self.rule_dialog.hide()

    def on_reset_fw_menu_activate(self, widget):
        print self.reset(True)

    def on_update_fw_menu_activate(self, widget):
        print self.application_update('all')

    def on_prefs_menu_activate(self, widget):
        if self.prefs_dialog.run():
            # loglevel
            level = self._get_combobox_value('logging_cbox').lower()
            self.set_loglevel(level)
            # default incoming
            policy = self._get_combobox_value('incoming_policy_cbox').lower()
            self.backend.set_default_policy(policy, 'incoming')
            # default outgoing
            policy = self._get_combobox_value('outgoing_policy_cbox').lower()
            self.backend.set_default_policy(policy, 'outgoing')
            # enable IPv6?
            cb = self.ui.get_object('enable_ipv6')
            self.enable_ipv6(cb.get_active())
            # reload firewall
            self.reload()
        self.prefs_dialog.hide()

    def on_main_window_destroy(self, widget):
        gtk.main_quit()


def main():
    ui = GtkFrontend()
    gtk.main()


if __name__ == '__main__':
    main()
