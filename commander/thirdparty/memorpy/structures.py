#!/usr/bin/env python
# -*- coding: UTF8 -*-

import sys
if sys.platform=="win32":
    from memorpy.WinStructures import *
else:
    from memorpy.LinStructures import *
