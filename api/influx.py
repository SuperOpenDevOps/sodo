#!/usr/bin/env python
# -*- coding:utf-8 -*-
# __author__ = Lyon


from core.view import RequestHandler, api, Param

class Get(RequestHandler):
    @api('/test')
    async def get(self):
        pass