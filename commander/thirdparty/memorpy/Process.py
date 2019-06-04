#!/usr/bin/env python
# -*- coding: UTF8 -*-

import sys
# from memorpy.BaseProcess import *
if sys.platform=='win32':
    from memorpy.WinProcess import WinProcess as Process
elif sys.platform=='darwin':
    from memorpy.OSXProcess import OSXProcess as Process
elif 'sunos' in sys.platform:
    from memorpy.SunProcess import SunProcess as Process
else:
    from memorpy.LinProcess import LinProcess as Process
