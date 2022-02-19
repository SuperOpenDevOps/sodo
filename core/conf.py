#!/usr/bin/env python
# -*- coding:utf-8 -*-
# __author__ = Lyon

import os
import logging


class Config:
    _default_conf = {
        'project_root': os.path.abspath(os.path.dirname(os.path.dirname(__file__))),
        'install_handlers': [],
        'install_handlers_name': {},
        'docs_username': 'admin',
        'docs_password': 'admin',
        'docs_global_params': [],
        'docs_global_headers': [],
        'docs_token_verify_expire': True,
        'docs_token_expire_days': 7,
        'docs_token_secret_key': '8i-!yfmt+hk@-$e7%wl2hx#!v7+rjdc%s8udl0a_*um0l)++y%',
        'static_path': 'static',
        'template_path': 'templates',
        'data_path': os.path.abspath(os.path.dirname(os.path.dirname(__file__))),
        'log_path': 'logs',
        'log_handler': [
            logging.INFO,
            logging.WARNING,
            logging.ERROR
        ],
        'log_format': '%(asctime)s - %(levelname)s - %(filename)s - %(funcName)s - %(lineno)s - %(message)s',
        'debug': True,
        'executor_thread_multiple': 5,
        'autoreload': False,
        'no_keep_alive': True,
        'on_finish_async': True,
        'cors_allow_origin': ['*'],
        'cors_allow_headers': ['*'],
        'cors_allow_method': ['POST', 'GET', 'OPTIONS']
    }

    def __init__(self):
        for key in dir(self):
            if not key.islower():
                self[key.lower()] = getattr(self, key)
        defaults = set(dir(self))
        for key in self._default_conf:
            if key not in defaults:
                self[key] = self._default_conf[key]

    def to_dict(self):
        """lower settings"""
        settings = {}
        for key in dir(self):
            if not key.startswith('__'):
                settings[key.lower()] = getattr(self, key)
        return settings

    def from_dict(self, d, **kwargs):
        assert issubclass(type(d), dict)
        d.update(kwargs)
        for key, value in d.items():
            self[key] = value

    def __getitem__(self, key):
        if hasattr(self, key):
            return getattr(self, key)
        raise AttributeError(key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def get(self, key, *default):
        if hasattr(self, key):
            return self[key]
        if len(default) != 0:
            return default[0]
        raise AttributeError(key)
