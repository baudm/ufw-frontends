
import os.path


ANY_ADDR = '0.0.0.0/0'
ANY_PORT = 'any'


def get_ui_path(ui_file):
    path = os.path.join('/usr', 'share', 'ufw-frontends', ui_file)
    if not os.path.exists(path):
        path = os.path.join('share', ui_file)
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
