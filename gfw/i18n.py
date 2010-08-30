import os.path
import gettext

import ufw.common


def translation():
    for var in ['LANGUAGE', 'LC_ALL', 'LC_MESSAGES', 'LANG']:
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
    return t
