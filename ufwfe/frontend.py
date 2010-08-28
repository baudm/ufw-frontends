
from ufw.frontend import UFWFrontend

from ufwfe.util import get_ip_version


class Frontend(UFWFrontend):

    def __init__(self):
        UFWFrontend.__init__(self, False)

    def enable_ipv6(self, use=True):
        conf = ('yes' if use else 'no')
        self.backend.set_default(self.backend.files['defaults'], 'IPV6', conf)

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

    def set_rule(self, rule, ip_version=None):
        """set_rule(rule, ip_version=None)

        Changes:
            * ip_version is optional
            * the recently added rule's position is reset
        """
        if ip_version is None:
            ip_version = get_ip_version(rule)
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
        res = UFWFrontend.set_rule(self, rule, ip_version)
        # Reset the positions of the recently inserted rule and adjacent rules
        if rule.position:
            s = rule.position - 2
            e = rule.position + 1
            for r in self.backend.get_rules()[s:e]:
                r.set_position(0)
        return res

    def update_rule(self, pos, rule):
        self.delete_rule(pos, True)
        rule.set_position(pos)
        self.set_rule(rule)

    def move_rule(self, old, new):
        if old == new:
            return
        rule = self.backend.get_rule_by_number(old).dup_rule()
        self.delete_rule(old, True)
        rule.set_position(new)
        self.set_rule(rule)
