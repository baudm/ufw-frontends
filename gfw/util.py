
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
    r.action = r.action.upper()
    r.direction = r.direction.upper()
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


def get_connections(append):
    with open('/proc/net/nf_conntrack', 'r') as f:
        for line in f:
            line = line.split()
            if line[2] != 'udp' and line[5] != 'ESTABLISHED':
                continue
            proto = line[2].upper()
            s = 5
            if line[2] == 'tcp':
                s += 1
            src = line[s].partition('=')[2]
            dst = line[s + 1].partition('=')[2]
            sport = line[s + 2].partition('=')[2]
            dport = line[s + 3].partition('=')[2]
            conn = (proto, src, sport, dst, dport)
            append(conn)
