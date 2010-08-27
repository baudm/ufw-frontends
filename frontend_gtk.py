#
# frontend_gtk.py: GTK frontend for ufw
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

from ufw.frontend import UFWFrontend
from ufw.common import UFWRule

from i18n import _

UI_FILE = 'ufw-gtk.glade'


class GtkFrontend(UFWFrontend):

    def __init__(self):
        UFWFrontend.__init__(self, False)
        self.ui = gtk.Builder()
        self.ui.add_from_file(UI_FILE)
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
        # rules model
        self.rules_model = self.ui.get_object('rules_model')
        self.refresh_rules_model()
        # enable multiple selections
        self.selection = self.ui.get_object('rules_view').get_selection()
        self.selection.set_mode(gtk.SELECTION_MULTIPLE)
        # comboboxes
        self.set_initial_prefs()
        # dialogs
        self.rule_dialog = self.ui.get_object('rule_dialog')
        self.prefs_dialog = self.ui.get_object('prefs_dialog')
        self.about_dialog = self.ui.get_object('about_dialog')
        main_window = self.ui.get_object('main_window')
        # set parent
        self.rule_dialog.set_transient_for(main_window)
        self.prefs_dialog.set_transient_for(main_window)
        self.about_dialog.set_transient_for(main_window)
        # connect signals and show main window
        self.ui.connect_signals(self)
        main_window.show_all()
        self._init_apps_model()

    def _init_apps_model(self):
        apps_model = self.ui.get_object('apps_model')
        apps = self.backend.profiles.keys()
        apps.sort()
        for app in apps:
            apps_model.append([app])

    def set_initial_prefs(self):
        cb = self.ui.get_object('enable_ipv6')
        conf = self.backend.defaults['ipv6']
        cb.set_active(conf == 'yes')
        self.set_combobox_defaults()

    def get_cbox_values(self, name):
        ls = self.ui.get_object(name).get_model()
        values = []
        for v in ls:
            values.append(v[0])
        return values

    def set_combobox_defaults(self):
        logging_opts = map(str.lower, self.get_cbox_values('logging_cbox'))
        policy_opts = map(str.lower, self.get_cbox_values('incoming_policy_cbox'))
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

    def _get_combobox_value(self, name):
        combobox = self.ui.get_object(name)
        model = combobox.get_model()
        active = combobox.get_active()
        if active >= 0:
            return model[active][0]

    def refresh_rules_model(self):
        self.rules_model.clear()
        app_rules = []
        i = 1
        for r in self.backend.get_rules():
            if r.dapp or r.sapp:
                t = r.get_app_tuple()
                if t in app_rules:
                    continue
                else:
                    app_rules.append(t)
                protocol = '-'
            else:
                protocol = r.protocol

            sport = (r.sapp if r.sapp else r.sport)
            dport = (r.dapp if r.dapp else r.dport)
            src = ('any' if r.src == '0.0.0.0/0' else r.src)
            dst = ('any' if r.dst == '0.0.0.0/0' else r.dst)
            row = [i, r.action.upper(), r.direction.upper(), protocol, src, sport, dst, dport]
            self.rules_model.append(row)
            i += 1

    def reload_firewall(self):
        if self.backend._is_enabled():
            self.set_enabled(False)
            self.set_enabled(True)
            self.refresh_rules_model()

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
        print 'toggle firewall'
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
        print 'reload firewall'
        self.reload_firewall()

    def on_insert_rule_clicked(self, widget):
        if self.backend._is_enabled():
            response = self.rule_dialog.run()
            self.rule_dialog.hide()

    def on_delete_rule_clicked(self, widget):
        if self.backend._is_enabled():
            for i in self.selection.get_selected_rows()[1]:
                self.delete_rule(i[0] + 1, True)
            self.refresh_rules_model()

    def on_rule_ok_clicked(self, widget):
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
        port = 'any'
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
        port = 'any'
        if self.ui.get_object('dst_port_custom_rbutton').get_active():
            port = self.ui.get_object('dst_port_custom_entry').get_text()
        elif self.ui.get_object('dst_app_rbutton').get_active():
            port = self._get_combobox_value('dst_app_cbox')
            rule.dapp = port
        rule.set_port(port, 'dst')

        ip_version = 'v4' # FIXME
        self.set_rule(rule, ip_version)
        self.refresh_rules_model()

    def on_help_menu_activate(self, widget):
        self.about_dialog.run()
        self.about_dialog.hide()

    def _process_prefs(self):
        # loglevel
        level = self._get_combobox_value('logging_cbox')
        self.set_loglevel(level)
        # default incoming
        policy = self._get_combobox_value('incoming_policy_cbox')
        self.backend.set_default_policy(policy, 'incoming')
        # default outgoing
        policy = self._get_combobox_value('outgoing_policy_cbox')
        self.backend.set_default_policy(policy, 'outgoing')
        # enable IPv6?
        cb = self.ui.get_object('enable_ipv6')
        conf = ('yes' if cb.get_active() else 'no')
        self.backend.set_default(self.backend.files['defaults'], 'IPV6', conf)
        # reload firewall
        self.reload_firewall()

    def on_reset_fw_menu_activate(self, widget):
        print self.reset(True)

    def on_update_fw_menu_activate(self, widget):
        print self.application_update('all')

    def on_prefs_menu_activate(self, widget):
        res = self.prefs_dialog.run()
        if res:
            self._process_prefs()
        self.prefs_dialog.hide()

    def on_main_window_destroy(self, widget):
        gtk.main_quit()


def main():
    GtkFrontend()
    gtk.main()


if __name__ == "__main__":
    main()
