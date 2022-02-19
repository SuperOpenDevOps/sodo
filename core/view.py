#!/usr/bin/env python
# -*- coding:utf-8 -*-
# __author__ = Lyon

import jwt
import json
import string
import inspect
import datetime
import functools
import importlib
import itertools
import tornado.web
import tornado.gen
import tornado.process
import concurrent.futures
from typing import Any
from core.app import config
from tornado.util import unicode_type
from tornado.escape import utf8, json_encode
from tornado.concurrent import run_on_executor

REQUEST_FAIL = (-1, 'FAIL')
REQUEST_SUCCESS = (0, 'SUCCESS')


def import_string(dotted_path):
    """
    Import a dotted module path and return the attribute/class designated by the
    last name in the path. Raise ImportError if the import failed.
    """
    try:
        module_path, class_name = dotted_path.rsplit('.', 1)
    except ValueError:
        msg = "%s doesn't look like a module path" % dotted_path
        raise ImportError(msg)

    module = importlib.import_module(module_path)

    try:
        return getattr(module, class_name)
    except AttributeError:
        msg = 'Module "%s" does not define a "%s" attribute/class' % (
            module_path, class_name)
        raise ImportError(msg)


def check_param(params):
    if not isinstance(params, (list, tuple)):
        raise TypeError('params type must be a list or tuple not %s.' % type(params))
    param_list = []
    for p in params:
        if isinstance(p, tuple):
            param_list.append(Param(*p))
        elif isinstance(p, Param):
            param_list.append(p)
        else:
            raise TypeError('api params type %s should be Param object or tuple not %s.' % (p, type(p).__name__))
    return param_list


def api(url, params=None, headers=None, desc='', display=True, owner=None):
    docs_headers = list(headers) if headers else []
    docs_headers.extend(config.docs_global_headers)
    docs_headers = check_param(docs_headers)

    docs_params = list(params) if params else []
    docs_params.extend(config.docs_global_params)
    docs_params = check_param(docs_params)

    def decorator(handler):
        method = handler.__name__
        route.register(
            url=url,
            desc=desc,
            author=owner,
            method=method,
            display=display,
            handler=handler,
            params=docs_params,
            headers=docs_headers
        )

        @functools.wraps(handler)
        async def request_handler(self, *args, **kwargs):
            self._docs_params[method] = {param['field_name']: param for param in docs_params}
            self._docs_headers[method] = {header['field_name']: header for header in docs_headers}
            return await handler(self, *args, **kwargs)

        return request_handler

    return decorator


class Endpoint(object):
    def __init__(self, pattern, handler, method, headers, params, name_parent, desc=None, author=None):
        self.pattern = pattern
        self.callback = handler
        self.docstring = self.get_doc()
        self.desc = desc
        self.name_parent = name_parent.split('.')[-1].title()
        alias = config.install_handlers_name.get(name_parent) or None
        if alias:
            self.name_parent = alias

        self.path = pattern
        self.methods = [method, ]
        self.params = {method: params}
        self.headers = {method: headers}
        self.author = author

    def __str__(self):
        return self.docstring

    @property
    def allowed_methods(self):
        return self.methods

    @property
    def template_method_length(self):
        return len(self.allowed_methods)

    @property
    def template_title_length(self):
        return 12 - len(self.allowed_methods)

    @property
    def params_json(self):
        return self.get_params_json(self.params)

    @property
    def headers_json(self):
        return self.get_params_json(self.headers)

    def get_params_json(self, param_dict):
        data = {}
        for method, params in param_dict.items():
            tmp = []
            for p in params:
                tmp.append(p.kwargs)
            data[method] = tmp
        return json.dumps({'data': data})

    def get_doc(self):
        doc = self.callback.__doc__
        if doc:
            doc = doc.replace('\n', '', 1)
        return doc


class Param(dict):
    """
    Parameters for building API documents.
    >>> Param('field_name', True, 'type', 'default_value', 'description')
    """

    def __init__(self, field_name, required, param_type, default='', description=''):
        """
        :param field_name:
        :param required:
        :param param_type: int, str, file
        :param default:
        :param description:
        """
        super(dict, self).__init__()
        self['field_name'] = field_name
        self['required'] = required
        if not isinstance(param_type, str):
            param_type = param_type.__name__
        self['param_type'] = param_type
        self['default'] = default
        self['description'] = description

    @property
    def kwargs(self):
        return {
            'field_name': self['field_name'],
            'required': self['required'],
            'param_type': self['param_type'],
            'default': self['default'],
            'description': self['description'],
        }


class _RouterMetaclass(type):
    """
    A singleton metaclass.
    """
    _instances = {}

    def __call__(self, *args, **kwargs):
        if self not in self._instances:
            self._instances[self] = super(_RouterMetaclass, self).__call__(*args, **kwargs)
        return self._instances[self]


class Router(metaclass=_RouterMetaclass):
    def __init__(self):
        self._registry = {}
        self.endpoints = []
        self.handlers_param = {}

    def register(self, **kwargs):
        handler = kwargs['handler']
        if self._registry.get(handler.__module__) is None:
            self._registry[handler.__module__] = [kwargs, ]
        else:
            self._registry[handler.__module__].append(kwargs)

    def get_handlers(self):
        """
        Return a list of URL patterns, given the registered handlers.
        """
        handlers_map = {}
        if config.debug:
            handlers_map['/tornado_docs'] = DocsHandler
            handlers_map['/tornado_docs/'] = DocsHandler
            handlers_map['/tornado_docs/login'] = DocsLoginHandler
            handlers_map['/tornado_docs/login/'] = DocsLoginHandler
            handlers_map['/tornado_docs/markdown'] = DocsMarkdownHandler
            handlers_map['/tornado_docs/markdown/'] = DocsMarkdownHandler

        for handler in config.install_handlers:
            import_string(handler + '.__name__')

        for module, param in self._registry.items():
            m = import_string(module)
            for p in param:
                func = p.get('handler')
                regex = p.get('url')
                params = p.get('params')
                headers = p.get('headers')
                desc = p.get('desc')
                display = p.get('display')
                author = p.get('author')

                handler_name, method = func.__qualname__.split('.')
                # Class
                handler = getattr(m, handler_name)  # type: tornado.web.RequestHandler
                method = method.upper()
                if method not in handler.SUPPORTED_METHODS:
                    # Method is invalid
                    raise type('HttpMethodError', (Exception,), {})('%s is not an HTTP method.' % method)

                if not regex.startswith('/'):
                    regex = '/' + regex

                if regex in handlers_map and handler != handlers_map[regex]:
                    continue

                # Compatible with '/' and ''
                if regex.endswith('/'):
                    handlers_map[regex.rstrip('/')] = handler
                else:
                    handlers_map[regex + '/'] = handler

                handlers_map[regex] = handler

                if display:
                    for endpoint in self.endpoints:
                        if endpoint.path == regex:
                            if method not in endpoint.methods:
                                endpoint.methods.append(method)
                                endpoint.params[method], endpoint.headers[method] = params, headers
                                break
                    else:
                        endpoint = Endpoint(
                            pattern=regex,
                            handler=handler,
                            method=method,
                            headers=headers,
                            params=params,
                            name_parent=module,
                            desc=desc,
                            author=author
                        )
                        if method != "OPTIONS":
                            endpoint.methods.append("OPTIONS")
                            endpoint.params["OPTIONS"], endpoint.headers["OPTIONS"] = [], []
                        self.endpoints.append(endpoint)
        return [(regex, handler) for regex, handler in handlers_map.items()]

    @property
    def handlers(self):
        if not hasattr(self, '_handlers'):
            self._handlers = self.get_handlers()
        return self._handlers


def before_request(f):
    """
    Add global middleware of before request.
    """
    RequestHandler.before_request_funcs.append(f)
    return f


def after_request(f):
    """Add global middleware of after request."""
    RequestHandler.after_request_funcs.append(f)
    return f


class RequestHandler(tornado.web.RequestHandler):
    __doc__ = ""

    current_user_id = None
    current_user = None
    org_id = None
    current_token = None
    _docs_params = {}
    _docs_headers = {}

    # Global Middleware
    before_request_funcs = []
    after_request_funcs = []

    executor = None

    def __init__(self, app, request, **kwargs):
        super(RequestHandler, self).__init__(app, request, **kwargs)

        if self.executor is None:
            self.__class__.executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=(tornado.process.cpu_count() * (app.config.executor_thread_multiple))
            )  # type: concurrent.futures.Executor
        self._chunk = None

    @property
    def app(self):
        return self.application

    def set_default_headers(self):
        allow_origin = self.application.config.cors_allow_origin
        if isinstance(self.application.config.cors_allow_origin, list):
            allow_origin = ','.join(self.application.config.cors_allow_origin)

        allow_headers = self.application.config.cors_allow_headers
        if isinstance(self.application.config.cors_allow_headers, list):
            allow_headers = ','.join(self.app.config.cors_allow_headers)

        allow_method = self.application.config.cors_allow_method
        if isinstance(self.application.config.cors_allow_method, list):
            allow_method = ','.join(self.application.config.cors_allow_method)

        self.set_header("Access-Control-Allow-Origin", allow_origin)
        self.set_header("Access-Control-Allow-Headers", allow_headers)
        self.set_header('Access-Control-Allow-Methods', allow_method)

    # type: tornado.web.RequestHandler.prepare
    async def prepare(self):
        if self.before_request_funcs:
            await tornado.gen.multi(self.before_request_funcs)
        await self.before_request()

    def add_callback(self, callback, *args, **kwargs):
        self.application.loop.add_callback(callback, *args, **kwargs)

    def on_finish(self):
        # async
        if self.application.config.on_finish_async:
            for func in self.after_request_funcs:
                func_args = inspect.getfullargspec(func).args
                if len(func_args):
                    self.add_callback(func, self)
                else:
                    self.add_callback(func)
        # sync
        else:
            for func in self.after_request_funcs:
                func_args = inspect.getfullargspec(func).args
                if len(func_args):
                    func(self)
                else:
                    func()
        if tornado.gen.is_future(self.after_request):
            self.add_callback(self.after_request)
        else:
            self.after_request()

    async def before_request(self):
        """
        Called at the beginning of a request before.
        """
        pass

    def after_request(self):
        """
        Called after the end of a request.
        """
        pass

    def _get_argument(self, name, default, source, strip=True):
        args = self._get_arguments(name, source, strip=strip)
        if not args:
            return default
        return args[-1]

    def get_headers(self, name, default=None, strip=True):
        s = self.request.headers.get(name, default)
        if strip:
            s = s.strip()
        return s

    def _get_arg(self, name, default=None, strip=True):
        param = self._docs_params.get(
            self.request.method.lower(), {}
        ).get(name, {'default': '', 'param_type': ''})  # type: Param

        argument = self.get_argument(name, default=default, strip=strip) or default  # type: String
        if param.get('required') and not argument:
            self.write_bad_request()
        return argument, param

    def get_arg(self, name, default=None, strip=True):
        (argument, param) = self._get_arg(name, default=default, strip=strip)
        # TODO: check args
        return argument

    def get_arg_int(self, name, default=None, strip=True):
        try:
            (str_arg, param) = self._get_arg(name, default=default, strip=strip)
            argument = int(str_arg) if str_arg else str_arg
            # TODO: check args
        except:
            self.write_bad_request()
        return argument

    def get_arg_float(self, name, default=None, strip=True):
        try:
            (str_arg, param) = self._get_arg(name, default=default, strip=strip)
            argument = float(str_arg) if str_arg else str_arg
            # TODO: check args
        except:
            self.write_bad_request()
        return argument

    def get_arg_dict(self, name, default=None, strip=True, max_length=None):
        try:
            str_arg = self.get_arg(name, default=default, strip=strip)
            argument = json.loads(str_arg) if str_arg else str_arg
            # TODO: check args
        except:
            self.write_bad_request()
        return argument

    def get_arg_datetime(self, name, default=None, strip=True):
        try:
            (datetime_string, param) = self._get_arg(name, default=default, strip=strip)
            if datetime_string is None:
                return None
            # TODO: check args
            return self.str_to_dt(datetime_string)
        except:
            self.write_bad_request()

    def str_to_dt(self, dt_str: str, format: str = "%Y-%m-%d %H:%M:%S"):
        """str object --> datetime object"""
        if "T" in dt_str and "Z" in dt_str:
            format += '.%fZ'
            return datetime.datetime.strptime(dt_str, format) + datetime.timedelta(
                hours=8)
        return datetime.datetime.strptime(dt_str, format)

    def _log(self):
        """self.finish() will second call."""
        # async
        if self.application.config.get("on_finish_async"):
            self.add_callback(self.log_request)
        # sync
        else:
            self.log_request()

    def log_request(self):
        if self.request.path.startswith('/tornado_docs'):
            return
        date_string = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        code = self.get_status() or "-"
        code = str(code)
        request_time = 1000.0 * self.request.request_time()

        header_params, body_params = '', ''

        if hasattr(self, '_docs_headers'):
            headers = self._docs_headers.get(self.request.method.lower(), {}).keys()
            if headers:
                header_params = '&'.join(
                    ['%s=%s' % (key, self.get_headers(key, default='')) for key in headers])
        if hasattr(self, '_docs_params'):
            keys = self._docs_params.get(self.request.method.lower(), {}).keys()
            if keys:
                body_params = '&'.join(['%s=%s' % (key, self.get_argument(key, default='')) for key in keys])
        params = '%s - %s' % (header_params, body_params) if (header_params or body_params) else ''

        if not hasattr(self, '_chunk'):
            self._chunk = None

        msg = '%s - [%s] - %s - %s - %.2f - %s - %s' % (self.request.remote_ip, date_string,
                                                        '%s - %s - %s' % (
                                                            self.request.method, self.request.uri,
                                                            self.request.version),
                                                        code, request_time, params, self._chunk)

        fmt_str = '\033[%d;%dm%s\033[0m'
        if code[0] == "1":  # 1xx - Informational
            msg = fmt_str % (1, 0, msg)
        elif code[0] == "2":  # 2xx - Success
            msg = fmt_str % (0, 37, msg)
        elif code == "304":  # 304 - Resource Not Modified
            msg = fmt_str % (0, 36, msg)
        elif code[0] == "3":  # 3xx - Redirection
            msg = fmt_str % (0, 32, msg)
        elif code == "404":  # 404 - Resource Not Found
            msg = fmt_str % (0, 33, msg)
        elif code[0] == "4":  # 4xx - Client Error
            msg = fmt_str % (1, 31, msg)
        else:  # 5xx, or any other response
            msg = fmt_str % (1, 0, msg)

        self.application.logger.info(msg)

    @property
    def logger(self):
        return self.application.logger

    def log_exception(self, typ, value, tb):
        """Override to customize logging of uncaught exceptions.

        By default logs instances of `HTTPError` as warnings without
        stack traces (on the ``tornado.general`` logger), and all
        other exceptions as errors with stack traces (on the
        ``tornado.application`` logger).

        .. versionadded:: 3.1
        """
        if isinstance(value, tornado.web.HTTPError):
            if value.log_message:
                format = "%d %s: " + value.log_message
                args = [value.status_code, self._request_summary()] + list(value.args)
                self.application.logger.warning(format, *args)
        else:
            self.application.logger.error(  # type: ignore
                "Uncaught exception %s\n%r",
                self._request_summary(),
                self.request,
                exc_info=(typ, value, tb),
            )

    def send_error(self, status_code: int = 500, **kwargs: Any):
        """Sends the given HTTP error code to the browser.

        If `flush()` has already been called, it is not possible to send
        an error, so this method will simply terminate the response.
        If output has been written but not yet flushed, it will be discarded
        and replaced with the error page.

        Override `write_error()` to customize the error page that is returned.
        Additional keyword arguments are passed through to `write_error`.
        """
        if self._headers_written:
            self.logger.error("Cannot send error response after headers written")
            if not self._finished:
                # If we get an error between writing headers and finishing,
                # we are unlikely to be able to finish due to a
                # Content-Length mismatch. Try anyway to release the
                # socket.
                try:
                    self.finish()
                except Exception:
                    self.logger.error("Failed to flush partial response", exc_info=True)
            return
        self.clear()

        reason = kwargs.get("reason")
        if "exc_info" in kwargs:
            exception = kwargs["exc_info"][1]
            if isinstance(exception, tornado.web.HTTPError) and exception.reason:
                reason = exception.reason
        if status_code >= 500:
            self.set_status(200, reason=reason)
        try:
            self.write_fail()
        except Exception:
            self.logger.error("Uncaught exception in write_error", exc_info=True)
        if not self._finished:
            self.finish()

    def write_fail(self, code=REQUEST_FAIL[0], msg=REQUEST_FAIL[1], data=""):
        """
        Request Fail. Return fail message.
        """
        chunk = {'code': code, 'data': data or dict(), 'msg': msg}
        return self.finish(chunk)

    def write_success(self, data=None, code=REQUEST_SUCCESS[0], msg=REQUEST_SUCCESS[1]):
        if data is None:
            data = dict()
        chunk = {'code': code, 'data': data, 'msg': msg}
        return self.finish(chunk)

    def write_bad_request(self):
        self.set_status(400, 'Bad Request!')
        raise tornado.web.Finish()

    def write_permission_denied(self):
        self.set_status(401, 'Unauthorized.')
        raise tornado.web.Finish()

    def write_not_found(self):
        self.set_status(404, 'Not Found')
        raise tornado.web.Finish()

    @run_on_executor
    def write_excel(self, data, filename):
        self.set_header('Content-Type', 'application/x-xls')
        self.set_header('Content-Disposition', 'attachment; filename=%s' % filename.encode("utf-8").decode("latin1"))
        self.write(data)
        return self.finish()

    async def options(self):
        return self.finish('OK')

    def write(self, chunk):
        """Writes the given chunk to the output buffer.

        To write the output to the network, use the `flush()` method below.

        If the given chunk is a dictionary, we write it as JSON and set
        the Content-Type of the response to be ``application/json``.
        (if you want to send JSON as a different ``Content-Type``, call
        ``set_header`` *after* calling ``write()``).

        Note that lists are not converted to JSON because of a potential
        cross-site security vulnerability.  All JSON output should be
        wrapped in a dictionary.  More details at
        http://haacked.com/archive/2009/06/25/json-hijacking.aspx/ and
        https://github.com/facebook/tornado/issues/1009
        """
        if self._finished:
            raise RuntimeError("Cannot write() after finish()")
        self._chunk = chunk
        if not isinstance(chunk, (bytes, unicode_type, dict)):
            message = "write() only accepts bytes, unicode, and dict objects"
            if isinstance(chunk, list):
                message += (
                        ". Lists not accepted for security reasons; see "
                        + "http://www.tornadoweb.org/en/stable/web.html#tornado.web.RequestHandler.write"  # noqa: E501
                )
            raise TypeError(message)
        if isinstance(chunk, dict):
            chunk = json_encode(chunk)
            self.set_header("Content-Type", "application/json; charset=UTF-8")
        chunk = utf8(chunk)
        self._write_buffer.append(chunk)


class PageNotFound(RequestHandler):
    async def prepare(self):
        self.set_status(404, reason='Not Found.')
        template = string.Template(
            '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
            '<meta http-equiv="X-UA-Compatible"content="IE=edge">'
            '<meta name="viewport"content="width=device-width, initial-scale=1">'
            '<style>body{background-color:rgb(236,236,236);'
            'color:#CD9B9B;font:100%"Lato",sans-serif;font-size:1.8rem;'
            'font-weight:300}.center{text-align:center}.header{font-size:10rem;font-weight:700;'
            'margin:2%0 2%0;text-shadow:5px 5px 5px#7f8c8d}.error{margin:-50px 0 2%0;font-size:6rem;'
            'text-shadow:5px 5px 5px#7f8c8d;font-weight:500}</style>'
            '<title>$code $message</title></head><body><section class="center"><article><h1 class="header">$code</h1>'
            '<p class="error">$message</p></article></section></body></html>'
        )
        self.finish(
            template.substitute(code=404, message=self._reason)
        )


def jwt_encode(app, data, secret_key, expires=None, issuer=""):
    if expires is None:
        expires = 7

    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=expires, seconds=0),  # 过期时间
        'iat': datetime.datetime.utcnow(),  # 发布时间
        'iss': issuer,
        'data': data
    }
    try:
        token = jwt.encode(
            payload,
            secret_key,
            algorithm='HS256'
        )
    except Exception as e:
        app.logger.error(e)
        return None
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token


def jwt_decode(app, token, secret_key, **options):
    try:
        payload = jwt.decode(token, secret_key, algorithms='HS256', options=options)
    except Exception as e:
        app.logger.error(e)
        return None
    return payload


class DocsHandler(RequestHandler):
    async def get(self):
        search = self.get_argument('search', default="")
        docs_token = self.get_cookie('docs_token', default="")
        if not docs_token or docs_token == 'undefined':
            return self.redirect('/tornado_docs/login')

        payload = jwt_decode(self.application, docs_token, self.application.config.docs_token_secret_key,
                             verify_exp=self.application.config.docs_token_verify_expire)
        if not payload or not payload.get('data'):
            return self.redirect('/tornado_docs/login')

        endpoints = []
        if search:
            for end in route.endpoints:
                if search in end.name_parent or search in end.path:
                    endpoints.append(end)
        else:
            endpoints = route.endpoints

        endpoints = itertools.groupby(endpoints, key=lambda x: x.name_parent)
        endpoints = [(name_parent, list(group)) for name_parent, group in endpoints]
        context = {
            'endpoints': endpoints,
            'query': search,
            'lower': lambda x: x.lower()
        }

        return self.render('docs/home.html', **context)


class DocsLoginHandler(RequestHandler):
    async def get(self):
        return self.render('docs/login.html')

    async def post(self):
        username = self.get_argument('username')
        password = self.get_argument('password')
        if username == self.application.config.docs_username and password == self.app.config.docs_password:
            data = {
                'login_time': datetime.datetime.now().strftime("%Y-%m-%D %H:%M:%S")
            }
            docs_token = jwt_encode(
                self.application,
                data,
                self.application.config.docs_token_secret_key,
                expires=self.application.config.docs_token_expire_days,
                issuer='Lyon'
            )
            return self.write_success({'docs_token': docs_token})
        return self.write_fail(msg="Username or password error.")


class DocsMarkdownHandler(RequestHandler):
    async def get(self):
        # TODO: 生成Markdown文档
        pass


route = Router()
