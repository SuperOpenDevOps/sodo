#!/usr/bin/env python
# -*- coding:utf-8 -*-
# __author__ = Lyon

import os
import sys
import time
import types
import logging
import tornado.gen
import tornado.web
import tornado.ioloop
import tornado.options
import concurrent.futures

PROJECT_ROOT = os.path.realpath(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(PROJECT_ROOT, os.pardir, os.pardir))

try:
    import config as project_conf
except:
    pass

app = None
config = None
environment = os.getenv('CURR_ENV', 'dev')


class Logger(object):
    def __init__(self, data_path, log_path, log_handler, log_format, debug=False):
        self.logger = logging.RootLogger(logging.DEBUG)
        self.logger.propagate = False

        if not log_format:
            log_format = '%(asctime)s - %(levelname)s - %(filename)s - %(funcName)s - %(lineno)s - %(message)s'
        self.format = logging.Formatter(log_format)

        self.data_path = data_path
        self.log_path = log_path
        self.log_handler = log_handler
        self.debug = debug

        for level in self.log_handler:
            level_name = logging._levelToName.get(level)
            self.add_handler(self.logger, level, level_name)
            self.add_console(self.logger, level)

        if self.debug:
            self.add_console(self.logger, logging.DEBUG)

    def add_handler(self, logger, level, level_name):
        file_name = time.strftime('%Y-%m-%d', time.localtime(time.time()))

        dir = self.data_path + os.sep + \
              self.log_path + os.sep + \
              level_name.lower()

        path = dir + os.sep + file_name + '.log'
        self.makedir(dir)
        handler = logging.FileHandler(path, encoding='UTF-8')
        filter = logging.Filter()
        filter.filter = lambda r: r.levelno == level

        handler.addFilter(filter)
        handler.setLevel(level)
        handler.setFormatter(self.format)

        logger.addHandler(handler)

    def add_console(self, logger, level):
        console = logging.StreamHandler()
        filter = logging.Filter()
        filter.filter = lambda r: r.levelno == level

        console.setLevel(level)
        console.addFilter(filter)
        logger.addHandler(console)

    def makedir(self, path):
        path = path.strip()
        if not os.path.exists(path):
            os.makedirs(path)
        return path


class Application(tornado.web.Application):
    def __init__(self, handlers, config, default_host=None, transforms=None, **settings):
        super(Application, self).__init__(handlers, default_host=default_host, transforms=transforms, **settings)

        self.config = config

        self.loop = tornado.ioloop.IOLoop.current()

        logger = Logger(self.config.data_path, self.config.log_path, self.config.log_handler,
                        self.config.log_format, self.config.debug).logger
        self.logger = logger

        self._machine = None
        self._sync_machine = None

        def _run_callback(self, callback):
            try:
                ret = callback()
                if ret is not None:
                    try:
                        ret = tornado.gen.convert_yielded(ret)
                    except tornado.gen.BadYieldError:
                        pass
                    else:
                        self.add_future(ret, self._discard_future_result)
            except concurrent.futures.CancelledError:
                pass
            except Exception:
                logger.error("Exception in callback %r", callback, exc_info=True)

        self.loop._run_callback = types.MethodType(_run_callback, self.loop)

    def run(self, port=8000, host='0.0.0.0'):
        self.port = port
        self.logger.info(' * Serving Tornado app "%s"' % __name__)
        self.logger.info(' * Environment: %s' % self.config.env)
        self.logger.info(' * Debug mode: %s' % ('on' if self.config.debug else 'off'))
        self.logger.info(f' * Logs cache in {self.config.data_path}/{self.config.log_path}')
        self.logger.info(' * Running on http://%s:%d/ (Press CTRL+C to quit)' % (host, port))
        if self.settings.get('debug'):
            self.logger.info(' * Tornado Docs running on http://%s:%d/tornado_docs' % (host, port))
        self.listen(port, host, xheaders=True)
        self.loop.start()

    def run_sync(self, func, time_out=None):
        return self.loop.run_sync(func, time_out)


def load_config(env):
    """Only load config, not app."""
    from core.conf import Config
    global config
    if config is not None:
        return config
    if isinstance(env, str):
        config_cls = project_conf.config_env.get(env)
        config = config_cls()
        assert issubclass(config_cls, Config), \
            "%s not have to_dict method." % config_cls.__name__
    elif isinstance(env, dict):
        config_cls = Config
        config = config_cls().from_dict(**env)
    else:
        raise TypeError

    config.env = env if isinstance(env, str) else env.__name__

    return config


def make_app(env=None):
    global app
    global environment
    if env is not None:
        config = load_config(env)
    else:
        config = load_config(environment)
    from core.view import route, PageNotFound, RequestHandler
    options = config.to_dict()
    options['logging'] = 'none'
    options['default_handler_class'] = PageNotFound
    options['log_function'] = RequestHandler.log_request
    app = Application(route.handlers, config, **options)

    return app
