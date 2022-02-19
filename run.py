#!/usr/bin/env python
# -*- coding:utf-8 -*-
# __author__ = Lyon

import sys
from core.app import make_app

app = make_app()

if __name__ == '__main__':
    options = {}
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            k, v = arg.strip('--').split('=', 1)
            options[k] = int(v)

    app.run(options.get('port', 8000))
