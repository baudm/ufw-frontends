import os
import gettext

import ufw.common

gettext.install(ufw.common.programName)
# Internationalization
gettext.bindtextdomain(ufw.common.programName,
                       os.path.join(ufw.common.trans_dir, 'messages'))
gettext.textdomain(ufw.common.programName)
_ = gettext.gettext
