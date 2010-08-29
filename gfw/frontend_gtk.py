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

import sys

import gtk

from ufw.common import UFWRule, UFWError

from gfw.frontend import Frontend
from gfw.i18n import _
from gfw.util import get_ui_path, get_formatted_rule
from gfw.util import ANY_ADDR, ANY_PORT


class GtkFrontend(Frontend):

    UI_FILE = 'ufw-gtk.glade'
    RESPONSE_OK = -5

    def __init__(self):
        super(GtkFrontend, self).__init__()
        self.ui = gtk.Builder()
        path = get_ui_path(self.UI_FILE)
        self.ui.add_from_file(path)
        self._init_action_groups()
        # models
        self.rules_model = self.ui.get_object('rules_model')
        self._update_rules_model()
        self._update_apps_model()
        # dialogs
        self.rule_dialog = self.ui.get_object('rule_dialog')
        self.prefs_dialog = self.ui.get_object('prefs_dialog')
        self.about_dialog = self.ui.get_object('about_dialog')
        self._init_prefs_dialog()
        self._init_main_window()
        # connect signals and show main window
        self.ui.connect_signals(self)
        main_window = self.ui.get_object('main_window')
        main_window.show_all()

    def _init_main_window(self):
        self.selection = self.ui.get_object('rules_view').get_selection()
        # set initial state of toggle button
        self._set_toggle_state(self.backend._is_enabled())

    def _init_prefs_dialog(self):
        # comboboxes
        logging_opts = map(str.lower, self._get_combobox_values('logging_cbox'))
        policy_opts = map(str.lower, self._get_combobox_values('incoming_policy_cbox'))
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

    def _init_action_groups(self):
        groups = {
            'rule_actions': [
                'rule_add', 'rule_delete', 'rule_edit',
                'rule_up', 'rule_down'
            ],
            'firewall_actions': [
                'firewall_reload', 'firewall_reset', 'firewall_update'
            ]
        }
        for group, actions in groups.iteritems():
            ag = self.ui.get_object(group)
            for action in actions:
                a = self.ui.get_object(action)
                ag.add_action(a)

    def _set_toggle_state(self, active):
        if active:
            label = 'Disable'
            short_label = 'Disable Firewall'
            stock_id = gtk.STOCK_STOP
        else:
            label = 'Enable'
            short_label = 'Enable Firewall'
            stock_id = gtk.STOCK_MEDIA_PLAY
        # Set action properties
        action = self.ui.get_object('firewall_toggle')
        action.set_active(active)
        action.set_label(_(label))
        action.set_short_label(_(short_label))
        action.set_stock_id(stock_id)
        # Enable/disable related controls
        self.ui.get_object('rules_view').set_sensitive(active)
        self.ui.get_object('rule_actions').set_sensitive(active)
        self.ui.get_object('firewall_actions').set_sensitive(active)

    def _get_combobox_values(self, name):
        model = self.ui.get_object(name).get_model()
        values = []
        for v in model:
            values.append(v[0])
        return values

    def _get_combobox_value(self, name):
        combobox = self.ui.get_object(name)
        model = combobox.get_model()
        active = combobox.get_active()
        if active >= 0:
            return model[active][0]

    def _set_combobox_value(self, name, value):
        values = map(str.lower, self._get_combobox_values(name))
        i = values.index(value.lower())
        cbox = self.ui.get_object(name)
        cbox.set_active(i)

    def _set_statusbar_text(self, text):
        sb = self.ui.get_object('statusbar')
        cid = sb.get_context_id('default context')
        sb.push(cid, text)

    def _show_dialog(self, msg, parent='main_window', type=gtk.MESSAGE_ERROR,
                        buttons=gtk.BUTTONS_CLOSE):
        widget = self.ui.get_object(parent)
        md = gtk.MessageDialog(widget,
                gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT,
                type, buttons, msg)
        res = md.run()
        md.destroy()
        return res

    def _update_rules_model(self):
        rules_model = self.ui.get_object('rules_model')
        rules_model.clear()
        for i, data in enumerate(self.get_rules()):
            idx, r = data
            r = get_formatted_rule(r)
            row = [i + 1, r.action, r.direction, r.protocol, r.src, r.sport, r.dst, r.dport, idx]
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
        if self.ui.get_object('protocol_cbox').get_sensitive():
            protocol = self._get_combobox_value('protocol_cbox').lower()
        else:
            protocol = 'any'
        rule = UFWRule(action, protocol)
        # position
        pos = self.ui.get_object('position_adjustment').get_value()
        rule.set_position(pos)
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

    def _restore_rule_dialog_defaults(self):
        position = self.ui.get_object('position_adjustment')
        # Max value should not exceed 'number of rules + 1'
        position.set_upper(len(self.rules_model) + 1)
        # Always set to the value of the currently selected row
        position.set_value(self._get_selected_rule_pos())
        # active radio buttons
        active = [
            'in_rbutton', 'src_addr_custom_rbutton', 'src_port_any_rbutton',
            'dst_addr_any_rbutton', 'dst_port_custom_rbutton'
        ]
        for k in active:
            self.ui.get_object(k).set_active(True)
        # blank text boxes
        blank = [
            'src_addr_custom_entry', 'src_port_custom_entry',
            'dst_addr_custom_entry', 'dst_port_custom_entry'
        ]
        for k in blank:
            self.ui.get_object(k).set_text('')
        # set combobox defaults
        cboxes = {
            'action_cbox': 0, 'protocol_cbox': 0, 'rule_logging_cbox': 0,
            'src_app_cbox': -1, 'dst_app_cbox': -1
        }
        for k, v in cboxes.iteritems():
            self.ui.get_object(k).set_active(v)

    def _load_rule_to_dialog(self, rule):
        self._restore_rule_dialog_defaults()
        # action
        self._set_combobox_value('action_cbox', rule.action)
        # direction
        in_rbutton = self.ui.get_object('in_rbutton')
        in_rbutton.set_active(rule.direction == 'in')
        # protocol
        if rule.sapp or rule.dapp:
            self._set_combobox_value('protocol_cbox', 'any')
        else:
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

    def _get_selected_rule_pos(self):
        model, itr = self.selection.get_selected()
        if not itr:
            return 0
        return model.get_path(itr)[0] + 1

    def _widgets_set_sensitive(self, prefix, active):
        for name in ('%s_custom_clear', '%s_custom_entry'):
            w = self.ui.get_object(name % (prefix, ))
            w.set_sensitive(active)
        # Set focus on the text entry
        self.rule_dialog.set_focus(w)

    def _clear_and_focus(self, prefix):
        name = '%s_custom_entry' % (prefix, )
        entry = self.ui.get_object(name)
        entry.set_text('')
        self.rule_dialog.set_focus(entry)

    # ---------------------- Application Actions -----------------------

    def on_rules_export_activate(self, action):
        pass

    def on_rules_import_activate(self, action):
        pass

    def on_quit_activate(self, action):
        gtk.main_quit()

    def on_prefs_dialog_show_activate(self, widget):
        if self.prefs_dialog.run() == self.RESPONSE_OK:
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
            self._set_statusbar_text(_('Preferences saved'))
        self.prefs_dialog.hide()

    def on_about_dialog_show_activate(self, widget):
        self.about_dialog.run()
        self.about_dialog.hide()

    # ------------------------ Firewall Actions ------------------------

    def on_firewall_toggle_toggled(self, action):
        if self.backend._is_enabled():
            res = self.set_enabled(False)
            self._set_statusbar_text(res)
            self._set_toggle_state(False)
        else:
            res = self.set_enabled(True)
            self._set_statusbar_text(res)
            self._set_toggle_state(True)

    def on_firewall_reload_activate(self, action):
        if self.reload():
            self._update_rules_model()

    def on_firewall_reset_activate(self, action):
        msg = _('Resetting all rules to installed defaults.\nProceed with operation?')
        res = self._show_dialog(msg, type=gtk.MESSAGE_WARNING, buttons=gtk.BUTTONS_YES_NO)
        if res == gtk.RESPONSE_YES:
            self.reset(True)
            self.rules_model.clear()
            self._set_toggle_state(False)
            self._set_statusbar_text(_('Firewall defaults restored'))

    def on_firewall_update_activate(self, action):
        res = self.application_update('all')
        if not res:
            res = _('Nothing to update')
        self._show_dialog(res, type=gtk.MESSAGE_INFO)

    # -------------------------- Rule Actions --------------------------

    def on_rule_add_activate(self, action):
        if not self.backend._is_enabled():
            return
        self._restore_rule_dialog_defaults()
        while True:
            if self.rule_dialog.run() == self.RESPONSE_OK:
                try:
                    rule = self._get_rule_from_dialog()
                except UFWError, e:
                    self._show_dialog(e.value, 'rule_dialog')
                    continue
                try:
                    res = self.set_rule(rule)
                except UFWError, e:
                    self._show_dialog(e.value, 'rule_dialog')
                    continue
                self._set_statusbar_text(res)
                self._update_rules_model()
            break
        self.rule_dialog.hide()

    def on_rule_edit_activate(self, action):
        if not self.backend._is_enabled():
            return
        pos = self._get_selected_rule_pos()
        if not pos:
            return
        rules = self.backend.get_rules()
        i = self.rules_model[pos - 1][8]
        self._load_rule_to_dialog(rules[i])
        while True:
            if self.rule_dialog.run() == self.RESPONSE_OK:
                try:
                    rule = self._get_rule_from_dialog()
                except UFWError, e:
                    self._show_dialog(e.value, 'rule_dialog')
                    continue
                try:
                    self.update_rule(pos, rule)
                except UFWError, e:
                    self._show_dialog(e.value, 'rule_dialog')
                    continue
                self._set_statusbar_text(_('Rule updated'))
                self._update_rules_model()
                self.selection.select_path(pos - 1)
            break
        self.rule_dialog.hide()

    def on_rule_delete_activate(self, action):
        if not self.backend._is_enabled():
            return
        pos = self._get_selected_rule_pos()
        if not pos:
            return
        msg = _('Delete rule at position %d?') % (pos, )
        res = self._show_dialog(msg, type=gtk.MESSAGE_QUESTION,
                    buttons=gtk.BUTTONS_YES_NO)
        if res == gtk.RESPONSE_NO:
            return
        try:
            res = self.delete_rule(pos, True)
        except UFWError, e:
            self._show_dialog(e.value)
        else:
            self._set_statusbar_text(res)
            self._update_rules_model()

    def on_rule_up_activate(self, action):
        if not self.backend._is_enabled():
            return
        pos = self._get_selected_rule_pos()
        if not pos:
            return
        new = pos - 1
        if new < 1:
            return
        self.move_rule(pos, new)
        self._update_rules_model()
        self.selection.select_path(new - 1)

    def on_rule_down_activate(self, action):
        if not self.backend._is_enabled():
            return
        pos = self._get_selected_rule_pos()
        if not pos:
            return
        new = pos + 1
        if new > len(self.rules_model):
            return
        self.move_rule(pos, new)
        self._update_rules_model()
        self.selection.select_path(new - 1)

    # ------------------------ Other Callbacks -------------------------

    def on_main_window_destroy(self, widget):
        self.ui.get_object('quit').activate()

    def on_rules_view_row_activated(self, widget, path, view_column):
        self.ui.get_object('rule_edit').activate()

    def on_src_addr_custom_rbutton_toggled(self, widget):
        self._widgets_set_sensitive('src_addr', widget.get_active())

    def on_dst_addr_custom_rbutton_toggled(self, widget):
        self._widgets_set_sensitive('dst_addr', widget.get_active())

    def on_src_port_custom_rbutton_toggled(self, widget):
        self._widgets_set_sensitive('src_port', widget.get_active())

    def on_dst_port_custom_rbutton_toggled(self, widget):
        self._widgets_set_sensitive('dst_port', widget.get_active())

    def on_src_addr_custom_clear_clicked(self, widget):
        self._clear_and_focus('src_addr')

    def on_dst_addr_custom_clear_clicked(self, widget):
        self._clear_and_focus('dst_addr')

    def on_src_port_custom_clear_clicked(self, widget):
        self._clear_and_focus('src_port')

    def on_dst_port_custom_clear_clicked(self, widget):
        self._clear_and_focus('dst_port')

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


def main():
    try:
        ui = GtkFrontend()
    except UFWError, e:
        sys.exit(e.value)
    else:
        gtk.main()


if __name__ == '__main__':
    main()
