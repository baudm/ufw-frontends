
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
        rule_num = 1
        for i, r in enumerate(self.backend.get_rules()):
            if r.dapp or r.sapp:
                t = r.get_app_tuple()
                if t in app_rules:
                    continue
                else:
                    app_rules.append(t)
            yield (i, rule_num, r)
            rule_num += 1

    def set_rule(self, rule, ip_version=None):
        """set_rule(rule, ip_version=None)

        Changes:
            * ip_version is optional
            * the recently added rule's position is reset
        """
        if ip_version is None:
            ip_version = get_ip_version(rule)
        UFWFrontend.set_rule(self, rule, ip_version)
        # If a rule is inserted, reset its position to 0
        if rule.position:
            rule = self.backend.get_rule_by_number(rule.position)
            rule.set_position(0)
