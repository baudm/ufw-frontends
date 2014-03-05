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

import gobject
import gtk

#import pynotify
#pynotify.init('ufw-frontends')

from ufw.common import UFWRule, UFWError

import gfw.util
import gfw.event
from gfw.frontend import Frontend


class Notifier(gfw.event.Notifier):

    def __init__(self, callback, inactive_handler):
        self._active = False
        try:
            gfw.event.Notifier.__init__(self, callback)
        except IOError:
            inactive_handler()
            return
        self._active = True
        self._w = gobject.io_add_watch(self._fd, gobject.IO_IN | gobject.IO_PRI,
                                       self._trigger)

    def __del__(self):
        if self._active:
            gfw.event.Notifier.__del__(self)
            gobject.source_remove(self._w)


class Builder(gtk.Builder):
    """Convenience class for easy access of GTK objects"""

    def __getattr__(self, name):
        attr = self.get_object(name)
        if attr is not None:
            return attr
        else:
            # Raise an AttributeError
            return self.__getattribute__(name)


class GtkFrontend(Frontend):

    UI_FILE = 'ufw-gtk.ui'
    RESPONSE_OK = -5
    MAX_EVENTS = 100

    def __init__(self):
        super(GtkFrontend, self).__init__()
        self.ui = Builder()
        path = gfw.util.get_ui_path(self.UI_FILE)
        self.ui.add_from_file(path)
        self._selection = self.ui.rules_view.get_selection()
        # models
        self._update_rules_model()
        self._update_apps_model()
        # actions and action groups
        self._init_action_groups()
        self._init_prefs_dialog()
        # connect signals
        self.ui.connect_signals(self)
        self._update_action_states()
        self._conn_timer = None
        def callback(data, notify=True):
            timestamp, event, conn = data
            #if notify:
                #n = pynotify.Notification(_('Firewall'), _('Blocked incoming connection from %s') % (conn['SRC'], ), gtk.STOCK_INFO)
                #n.show()
            if len(self.ui.events_model) > self.MAX_EVENTS:
                i = self.ui.events_model.get_iter_first()
                self.ui.events_model.remove(i)
            spt = conn.get('SPT', '')
            dpt = conn.get('DPT', '')
            data = (timestamp, event, conn['IN'], conn['OUT'], conn['PROTO'],
                    conn['SRC'], spt, conn['DST'], dpt)
            self.ui.events_model.append(data)
        self._notifier = Notifier(callback,
                lambda: self.ui.events_view.set_sensitive(False))
        self.ui.main_window.show_all()
        ## FIXME: for the 0.3.0 release, hide the tab for the connections view
        page = self.ui.view.get_nth_page(2)
        page.hide()

    def _init_prefs_dialog(self):
        conf = self.backend.defaults
        # Get current values
        logging_opts = map(str.lower, self._get_combobox_values('logging_cbox'))
        policy_opts = map(str.lower, self._get_combobox_values('incoming_policy_cbox'))
        logging = logging_opts.index(conf['loglevel'])
        default_incoming = policy_opts.index(self.backend.get_default_policy('input'))
        default_outgoing = policy_opts.index(self.backend.get_default_policy('output'))
        # Set values to comboboxes
        self.ui.logging_cbox.set_active(logging)
        self.ui.incoming_policy_cbox.set_active(default_incoming)
        self.ui.outgoing_policy_cbox.set_active(default_outgoing)
        # checkboxes
        self.ui.enable_ipv6.set_active(conf['ipv6'] == 'yes')
        # IPT modules
        try:
            modules = conf['ipt_modules']
        except KeyError:
            modules = ''
        enable = ('nf_conntrack_ftp' in modules and 'nf_nat_ftp' in modules)
        self.ui.mod_ftp_chkbox.set_active(enable)
        enable = ('nf_conntrack_irc' in modules and 'nf_nat_irc' in modules)
        self.ui.mod_irc_chkbox.set_active(enable)
        enable = ('nf_conntrack_netbios_ns' in modules)
        self.ui.mod_netbios_chkbox.set_active(enable)
        enable = ('nf_conntrack_pptp' in modules)
        self.ui.mod_pptp_chkbox.set_active(enable)
        enable = ('nf_conntrack_sane' in modules)
        self.ui.mod_saned_chkbox.set_active(enable)

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

    def _update_action_states(self):
        active = self.backend._is_enabled()
        if active:
            label = _('Disable')
            short_label = _('Disable Firewall')
            stock_id = gtk.STOCK_STOP
        else:
            label = _('Enable')
            short_label = _('Enable Firewall')
            stock_id = gtk.STOCK_MEDIA_PLAY
        # Set action properties
        action = self.ui.firewall_toggle
        # Temporarily block the handler to prevent infinite loops
        action.handler_block_by_func(self.on_firewall_toggle_toggled)
        action.set_active(active)
        action.handler_unblock_by_func(self.on_firewall_toggle_toggled)
        action.set_label(label)
        action.set_short_label(short_label)
        action.set_stock_id(stock_id)
        # Enable/disable related controls
        self.ui.rules_view.set_sensitive(active)
        self.ui.rule_actions.set_sensitive(active)
        self.ui.firewall_actions.set_sensitive(active)

    def _get_combobox_values(self, name):
        model = self.ui.get_object(name).get_model()
        values = [v[0] for v in model]
        return values

    def _get_combobox_value(self, name):
        combobox = self.ui.get_object(name)
        model = combobox.get_model()
        active = combobox.get_active()
        if active >= 0:
            return model[active][0]

    def _set_combobox_value(self, name, value):
        values = map(str.lower, self._get_combobox_values(name))
        try:
            i = values.index(value.lower())
        except ValueError:
            # value is not an option; do nothing and just return.
            return
        cbox = self.ui.get_object(name)
        cbox.set_active(i)

    def _set_statusbar_text(self, text):
        cid = self.ui.statusbar.get_context_id('default context')
        mid = self.ui.statusbar.push(cid, text)
        # Remove message after 5 seconds
        gobject.timeout_add_seconds(5, self.ui.statusbar.remove_message, cid, mid)

    def _show_dialog(self, msg, parent=None, type=gtk.MESSAGE_ERROR,
                        buttons=gtk.BUTTONS_CLOSE):
        if parent is None:
            parent = self.ui.main_window
        md = gtk.MessageDialog(parent,
                gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT,
                type, buttons, msg)
        res = md.run()
        md.destroy()
        return res

    def _update_conns_model(self):
        self.ui.conns_model.clear()
        gfw.util.get_connections(self.ui.conns_model.append)
        return True

    def _update_rules_model(self):
        self.ui.rules_model.clear()
        for i, data in enumerate(self.get_rules()):
            idx, r = data
            r = gfw.util.get_formatted_rule(r)
            row = (i + 1, r.action, r.direction, r.protocol, r.src, r.sport,
                    r.dst, r.dport, idx)
            self.ui.rules_model.append(row)

    def _update_apps_model(self):
        self.ui.apps_model.clear()
        apps = self.backend.profiles.keys()
        apps.sort()
        for app in apps:
            self.ui.apps_model.append([app])

    def _get_rule_from_dialog(self):
        action = self._get_combobox_value('action_cbox').lower()
        if self.ui.protocol_cbox.get_sensitive():
            protocol = self._get_combobox_value('protocol_cbox').lower()
        else:
            protocol = 'any'
        rule = UFWRule(action, protocol)
        # position
        pos = self.ui.position_adjustment.get_value()
        rule.set_position(pos)
        # direction
        direction = ('in' if self.ui.in_rbutton.get_active() else 'out')
        rule.set_direction(direction)
        # logtype
        log_map = {'Off': '', 'New Connections': 'log', 'Packets': 'log-all'}
        logtype = log_map[self._get_combobox_value('rule_logging_cbox')]
        rule.set_logtype(logtype)
        # src
        if self.ui.src_addr_custom_rbutton.get_active():
            addr = self.ui.src_addr_custom_entry.get_text()
            rule.set_src(addr)
        # src port
        port = gfw.util.ANY_PORT
        if self.ui.src_port_custom_rbutton.get_active():
            port = self.ui.src_port_custom_entry.get_text()
        elif self.ui.src_app_rbutton.get_active():
            port = self._get_combobox_value('src_app_cbox')
            rule.sapp = port
        rule.set_port(port, 'src')
        # dst
        if self.ui.dst_addr_custom_rbutton.get_active():
            addr = self.ui.dst_addr_custom_entry.get_text()
            rule.set_dst(addr)
        # dst port
        port = gfw.util.ANY_PORT
        if self.ui.dst_port_custom_rbutton.get_active():
            port = self.ui.dst_port_custom_entry.get_text()
        elif self.ui.dst_app_rbutton.get_active():
            port = self._get_combobox_value('dst_app_cbox')
            rule.dapp = port
        rule.set_port(port, 'dst')
        return rule

    def _restore_rule_dialog_defaults(self):
        # Max value should not exceed 'number of rules + 1'
        self.ui.position_adjustment.set_upper(len(self.ui.rules_model) + 1)
        # Always set to the value of the currently selected row
        self.ui.position_adjustment.set_value(self._get_selected_rule_pos())
        # Set active radio buttons
        self.ui.in_rbutton.set_active(True)
        self.ui.src_addr_custom_rbutton.set_active(True)
        self.ui.src_port_any_rbutton.set_active(True)
        self.ui.dst_addr_any_rbutton.set_active(True)
        self.ui.dst_port_custom_rbutton.set_active(True)
        # Clear text extries
        self.ui.src_addr_custom_entry.set_text('')
        self.ui.src_port_custom_entry.set_text('')
        self.ui.dst_addr_custom_entry.set_text('')
        self.ui.dst_port_custom_entry.set_text('')
        # Set combobox defaults
        self.ui.action_cbox.set_active(0)
        self.ui.protocol_cbox.set_active(0)
        self.ui.rule_logging_cbox.set_active(0)
        self.ui.src_app_cbox.set_active(-1)
        self.ui.dst_app_cbox.set_active(-1)

    def _load_rule_to_dialog(self, rule):
        self._restore_rule_dialog_defaults()
        # When editing, max position should be equal to the number of rules
        self.ui.position_adjustment.set_upper(len(self.ui.rules_model))
        # action
        self._set_combobox_value('action_cbox', rule.action)
        # direction
        if rule.direction == 'in':
            self.ui.in_rbutton.set_active(True)
        else:
            self.ui.out_rbutton.set_active(True)
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
        if rule.src == gfw.util.ANY_ADDR:
            self.ui.src_addr_any_rbutton.set_active(True)
            addr = ''
        else:
            self.ui.src_addr_custom_rbutton.set_active(True)
            addr = rule.src
        self.ui.src_addr_custom_entry.set_text(addr)
        # src port
        if rule.sapp:
            self.ui.src_app_rbutton.set_active(True)
            self._set_combobox_value('src_app_cbox', rule.sapp)
        elif rule.sport == gfw.util.ANY_PORT:
            self.ui.src_port_any_rbutton.set_active(True)
        else:
            self.ui.src_port_custom_rbutton.set_active(True)
            self.ui.src_port_custom_entry.set_text(rule.sport)
        # dst
        if rule.dst == gfw.util.ANY_ADDR:
            self.ui.dst_addr_any_rbutton.set_active(True)
            addr = ''
        else:
            self.ui.dst_addr_custom_rbutton.set_active(True)
            addr = rule.dst
        self.ui.dst_addr_custom_entry.set_text(addr)
        # src port
        if rule.dapp:
            self.ui.dst_app_rbutton.set_active(True)
            self._set_combobox_value('dst_app_cbox', rule.dapp)
        elif rule.dport == gfw.util.ANY_PORT:
            self.ui.dst_port_any_rbutton.set_active(True)
        else:
            self.ui.dst_port_custom_rbutton.set_active(True)
            self.ui.dst_port_custom_entry.set_text(rule.dport)

    def _get_selected_rule_pos(self):
        model, itr = self._selection.get_selected()
        if not itr:
            return 0
        return model.get_path(itr)[0] + 1

    def _create_file_chooser_dialog(self, save=True):
        if save:
            action = gtk.FILE_CHOOSER_ACTION_SAVE
            ok_button = gtk.STOCK_SAVE_AS
            title = _('Export Rules')
        else:
            action = gtk.FILE_CHOOSER_ACTION_OPEN
            ok_button = gtk.STOCK_OPEN
            title = _('Import Rules')
        buttons = (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                    ok_button, gtk.RESPONSE_OK)
        dlg = gtk.FileChooserDialog(title, self.ui.main_window, action, buttons)
        # Shell scripts filter
        f = gtk.FileFilter()
        f.set_name('Shell scripts')
        f.add_mime_type('application/x-sh')
        f.add_pattern('*.sh')
        dlg.add_filter(f)
        # All files filter
        f = gtk.FileFilter()
        f.set_name('All files')
        f.add_pattern('*')
        dlg.add_filter(f)
        return dlg

    # ---------------------- Application Actions -----------------------

    def on_rules_export_activate(self, action):
        chooser = self._create_file_chooser_dialog()
        while True:
            if chooser.run() == gtk.RESPONSE_OK:
                filename = chooser.get_filename()
                try:
                    self.export_rules(filename)
                except IOError as e:
                    self._show_dialog(e.strerror, chooser)
                    continue
                else:
                    self._set_statusbar_text(_('Rules exported'))
            break
        chooser.destroy()

    def on_rules_import_activate(self, action):
        chooser = self._create_file_chooser_dialog(False)
        while True:
            if chooser.run() == gtk.RESPONSE_OK:
                filename = chooser.get_filename()
                try:
                    self.import_rules(filename)
                except IOError as e:
                    self._show_dialog(e.strerror, chooser)
                    continue
                except UFWError as e:
                    self._show_dialog(e.value, chooser)
                    continue
                else:
                    self._set_statusbar_text(_('Rules imported'))
            break
        chooser.destroy()
        self._update_rules_model()

    def on_quit_activate(self, action):
        gtk.main_quit()

    def on_prefs_dialog_show_activate(self, action):
        self._init_prefs_dialog()
        if self.ui.prefs_dialog.run() == self.RESPONSE_OK:
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
            self.config_ipv6(self.ui.enable_ipv6.get_active())
            # Enable additional IPT modules?
            # FTP
            self.config_ipt_module('nf_conntrack_ftp',
                                   self.ui.mod_ftp_chkbox.get_active())
            self.config_ipt_module('nf_nat_ftp',
                                   self.ui.mod_ftp_chkbox.get_active())
            # IRC
            self.config_ipt_module('nf_conntrack_irc',
                                   self.ui.mod_irc_chkbox.get_active())
            self.config_ipt_module('nf_nat_irc',
                                   self.ui.mod_irc_chkbox.get_active())
            # NetBIOS
            self.config_ipt_module('nf_conntrack_netbios_ns',
                                   self.ui.mod_netbios_chkbox.get_active())
            # PPTP
            self.config_ipt_module('nf_conntrack_pptp',
                                   self.ui.mod_pptp_chkbox.get_active())
            # saned
            self.config_ipt_module('nf_conntrack_sane',
                                   self.ui.mod_saned_chkbox.get_active())
            # reload firewall
            self.reload()
            self._set_statusbar_text(_('Preferences saved'))
        self.ui.prefs_dialog.hide()

    def on_reports_dialog_show_activate(self, action):
        self.ui.reports_dialog.run()
        self.ui.reports_dialog.hide()
        # Reset
        self.ui.report_cbox.set_active(-1)
        self.ui.reports_buffer.set_text('')

    def on_report_cbox_changed(self, widget):
        active = widget.get_active()
        model = widget.get_model()
        report = model[active][0].split('-')[0]
        if report != 'listening':
            try:
                res = self.get_show_raw(report)
            except UFWError:
                res = ''
        else:
            res = self.get_show_listening()
        self.ui.reports_buffer.set_text(res)

    def on_about_dialog_show_activate(self, action):
        self.ui.about_dialog.run()
        self.ui.about_dialog.hide()

    # ------------------------ Firewall Actions ------------------------

    def on_firewall_toggle_toggled(self, action):
        res = self.set_enabled(not self.backend._is_enabled())
        self._set_statusbar_text(res)
        self._update_action_states()

    def on_firewall_reload_activate(self, action):
        if self.reload():
            self._update_rules_model()
            self._set_statusbar_text(_('Firewall reloaded'))

    def on_firewall_reset_activate(self, action):
        msg = _('Resetting all rules to installed defaults.\nProceed with operation?')
        res = self._show_dialog(msg, type=gtk.MESSAGE_WARNING, buttons=gtk.BUTTONS_YES_NO)
        if res == gtk.RESPONSE_YES:
            self.reset(True)
            self.ui.rules_model.clear()
            self._update_action_states()
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
            if self.ui.rule_dialog.run() == self.RESPONSE_OK:
                try:
                    rule = self._get_rule_from_dialog()
                except UFWError as e:
                    self._show_dialog(e.value, self.ui.rule_dialog)
                    continue
                try:
                    res = self.set_rule(rule)
                except UFWError as e:
                    self._show_dialog(e.value, self.ui.rule_dialog)
                    continue
                self._set_statusbar_text(res)
                self._update_rules_model()
            break
        self.ui.rule_dialog.hide()

    def on_rule_edit_activate(self, action):
        if not self.backend._is_enabled():
            return
        pos = self._get_selected_rule_pos()
        if not pos:
            return
        rules = self.backend.get_rules()
        i = self.ui.rules_model[pos - 1][8]
        self._load_rule_to_dialog(rules[i])
        while True:
            if self.ui.rule_dialog.run() == self.RESPONSE_OK:
                try:
                    rule = self._get_rule_from_dialog()
                except UFWError as e:
                    self._show_dialog(e.value, self.ui.rule_dialog)
                    continue
                try:
                    self.update_rule(pos, rule)
                except UFWError as e:
                    self._show_dialog(e.value, self.ui.rule_dialog)
                    continue
                self._set_statusbar_text(_('Rule updated'))
                self._update_rules_model()
                self._selection.select_path(pos - 1)
            break
        self.ui.rule_dialog.hide()

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
        except UFWError as e:
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
        self._selection.select_path(new - 1)

    def on_rule_down_activate(self, action):
        if not self.backend._is_enabled():
            return
        pos = self._get_selected_rule_pos()
        if not pos:
            return
        new = pos + 1
        if new > len(self.ui.rules_model):
            return
        self.move_rule(pos, new)
        self._update_rules_model()
        self._selection.select_path(new - 1)

    # ------------------------- Event Actions --------------------------

    def on_event_allow_activate(self, action):
        if not self.backend._is_enabled():
            return
        model, itr = self.ui.events_view.get_selection().get_selected()
        i = model.get_path(itr)[0]
        data = tuple(self.ui.events_model[i])
        proto, src, sport = data[4:7]
        dst, dport = data[7:]
        self._restore_rule_dialog_defaults()
        # position
        self.ui.position_adjustment.set_value(self.ui.position_adjustment.get_upper())
        # protocol
        self._set_combobox_value('protocol_cbox', proto)
        # src
        self.ui.src_addr_custom_entry.set_text(src)
        # sport
        self.ui.src_port_custom_entry.set_text(sport)
        # dst
        self.ui.dst_addr_custom_entry.set_text(dst)
        self.ui.dst_addr_custom_rbutton.set_active(True)
        # dport
        self.ui.dst_port_custom_entry.set_text(dport)
        while True:
            if self.ui.rule_dialog.run() == self.RESPONSE_OK:
                try:
                    rule = self._get_rule_from_dialog()
                except UFWError as e:
                    self._show_dialog(e.value, self.ui.rule_dialog)
                    continue
                try:
                    res = self.set_rule(rule)
                except UFWError as e:
                    self._show_dialog(e.value, self.ui.rule_dialog)
                    continue
                self._set_statusbar_text(res)
                self._update_rules_model()
            break
        self.ui.rule_dialog.hide()

    # --------------------- Main Window Callbacks ----------------------

    def on_main_window_destroy(self, widget):
        self.ui.quit.activate()

    def on_rules_view_row_activated(self, widget, path, view_column):
        self.ui.rule_edit.activate()

    def on_rules_view_button_press_event(self, widget, event):
        # Show popup on right-click only
        if event.button == 3:
            self.ui.rule_menu.popup(None, None, None, event.button, event.time)

    def on_events_view_button_press_event(self, widget, event):
        # Show popup on right-click only
        if event.button == 3:
            self.ui.event_menu.popup(None, None, None, event.button, event.time)

    def on_view_switch_page(self, widget, page, page_num):
        if page_num == 2:
            self._update_conns_model()
            self._conn_timer = gobject.timeout_add_seconds(5, self._update_conns_model)
        elif self._conn_timer is not None:
            gobject.source_remove(self._conn_timer)

    # --------------------- Rule Dialog Callbacks ----------------------

    def _custom_rbutton_toggled(self, prefix, active):
        for name in ('%s_custom_clear', '%s_custom_entry'):
            w = self.ui.get_object(name % (prefix, ))
            w.set_sensitive(active)
        # Set focus on the text entry
        if active:
            self.ui.rule_dialog.set_focus(w)

    def on_src_addr_custom_rbutton_toggled(self, widget):
        self._custom_rbutton_toggled('src_addr', widget.get_active())

    def on_dst_addr_custom_rbutton_toggled(self, widget):
        self._custom_rbutton_toggled('dst_addr', widget.get_active())

    def on_src_port_custom_rbutton_toggled(self, widget):
        self._custom_rbutton_toggled('src_port', widget.get_active())

    def on_dst_port_custom_rbutton_toggled(self, widget):
        self._custom_rbutton_toggled('dst_port', widget.get_active())

    def _custom_clear_clicked(self, prefix):
        name = '%s_custom_entry' % (prefix, )
        entry = self.ui.get_object(name)
        entry.set_text('')
        self.ui.rule_dialog.set_focus(entry)

    def on_src_addr_custom_clear_clicked(self, widget):
        self._custom_clear_clicked('src_addr')

    def on_dst_addr_custom_clear_clicked(self, widget):
        self._custom_clear_clicked('dst_addr')

    def on_src_port_custom_clear_clicked(self, widget):
        self._custom_clear_clicked('src_port')

    def on_dst_port_custom_clear_clicked(self, widget):
        self._custom_clear_clicked('dst_port')

    def _app_rbutton_toggled(self, prefix, active):
        for name in ['%s_app_cbox', '%s_app_info']:
            w = self.ui.get_object(name % (prefix, ))
            w.set_sensitive(active)
        # 'Toggle' prefix
        prefix = ('dst' if prefix == 'src' else 'src')
        name = '%s_app_rbutton' % (prefix, )
        rbutton = self.ui.get_object(name)
        sensitive = (not active and not rbutton.get_active())
        self.ui.protocol_cbox.set_sensitive(sensitive)

    def on_src_app_rbutton_toggled(self, widget):
        self._app_rbutton_toggled('src', widget.get_active())

    def on_dst_app_rbutton_toggled(self, widget):
        self._app_rbutton_toggled('dst', widget.get_active())

    def _app_info_clicked(self, prefix):
        app = self._get_combobox_value('%s_app_cbox' % (prefix, ))
        if app is not None:
            info = self.get_application_info(app)
            self._show_dialog(info, self.ui.rule_dialog, gtk.MESSAGE_INFO)

    def on_src_app_info_clicked(self, widget):
        self._app_info_clicked('src')

    def on_dst_app_info_clicked(self, widget):
        self._app_info_clicked('dst')


def main():
    try:
        ui = GtkFrontend()
    except UFWError as e:
        sys.exit(e.value)
    else:
        gtk.main()


if __name__ == '__main__':
    main()
