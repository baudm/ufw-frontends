import os.path
import gettext

import ufw.applications
import ufw.backend
import ufw.backend_iptables
import ufw.common
import ufw.frontend
import ufw.parser
import ufw.util


def ufw_localize():
    # Just return if the _() function is already installed
    if hasattr(ufw.common, '_'):
        return
    lang = ''
    for var in ('LANGUAGE', 'LC_ALL', 'LC_MESSAGES', 'LANG'):
        lang = os.getenv(var)
        if lang:
            break
    # Use only the first language
    lang = lang.split(':')[0]
    lang = os.path.splitext(lang)[0]
    path = os.path.join(ufw.common.trans_dir, 'messages', lang + '.mo')
    try:
        f = open(path, 'r')
    except IOError:
        t = gettext.NullTranslations()
    else:
        t = gettext.GNUTranslations(f)
        f.close()
    # Manually install the _() function for module-wide l10n
    x = t.gettext
    ufw.applications._ = x
    ufw.backend_iptables._ = x
    ufw.backend._ = x
    ufw.common._ = x
    ufw.frontend._ = x
    ufw.parser._ = x
    ufw.util._ = x
