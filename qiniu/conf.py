# -*- coding: utf-8 -*-

ACCESS_KEY = ""
SECRET_KEY = ""
#ACCESS_KEY = "cheVOLAUN6S74d5GHvBPqJEUzJ8OkO_9VBxUEPGh"
#SECRET_KEY = "LCYM9WWqiwLT-4R1LQ_BjMMZO56WGkdpsHcxKUKr"

RS_HOST = "rs.qbox.me"
RSF_HOST = "rsf.qbox.me"
UP_HOST = "up.qiniu.com"

from . import __version__
import platform

sys_info = "%s/%s" % (platform.system(), platform.machine())
py_ver = platform.python_version()

USER_AGENT = "QiniuPython/%s (%s) Python/%s" % (__version__, sys_info, py_ver)
