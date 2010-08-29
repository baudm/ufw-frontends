
import os.path

import ufw.common


ANY_ADDR = '0.0.0.0/0'
ANY_PORT = 'any'


def get_ui_path(ui_file):
    if False:
        path = os.path.join(ufw.common.share_dir, 'ui', ui_file)
    else:
        path = os.path.join('ui', ui_file)
    return path


def get_formatted_rule(rule):
    r = rule.dup_rule()
    r.action = r.action.title()
    r.direction = r.direction.title()
    if r.dapp or r.sapp:
        r.protocol = ''
        if r.sapp:
            r.sport = r.sapp
        if r.dapp:
            r.dport = r.dapp
    if r.protocol == 'any':
        r.protocol = '*'
    else:
        r.protocol = r.protocol.upper()
    if r.sport == ANY_PORT:
        r.sport = '*'
    if r.dport == ANY_PORT:
        r.dport = '*'
    if r.src == ANY_ADDR:
        r.src = '*'
    if r.dst == ANY_ADDR:
        r.dst = '*'
    return r
