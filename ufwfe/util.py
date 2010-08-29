
import os.path

from ufw.util import valid_address
from ufw.common import UFWError, share_dir

from ufwfe.i18n import _


ANY_ADDR = '0.0.0.0/0'
ANY_PORT = 'any'


def get_ui_path(ui_file):
    if False:
        path = os.path.join(share_dir, 'ui', ui_file)
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


def get_ip_version(rule):
    """Determine IP version of rule
    Algorithm extracted from ufw.parser.UFWCommandRule.parse
    """
    if rule.src == ANY_ADDR:
        from_type = 'any'
    else:
        from_type = ('v6' if valid_address(rule.src, '6') else 'v4')

    if rule.dst == ANY_ADDR:
        to_type = 'any'
    else:
        to_type = ('v6' if valid_address(rule.dst, '6') else 'v4')

    # Figure out the type of rule (IPv4, IPv6, or both) this is
    if from_type == 'any' and to_type == 'any':
        ip_version = 'both'
    elif from_type != 'any' and to_type != 'any' and from_type != to_type:
        err_msg = _("Mixed IP versions for 'from' and 'to'")
        raise UFWError(err_msg)
    elif from_type != 'any':
        ip_version = from_type
    elif to_type != 'any':
        ip_version = to_type

    return ip_version
