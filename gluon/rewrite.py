#!/bin/env python
# -*- coding: utf-8 -*-

"""
This file is part of web2py Web Framework (Copyrighted, 2007-2010).
Developed by Massimo Di Pierro <mdipierro@cs.depaul.edu>.
License: GPL v2
"""

import os
import re
import logging
import traceback

LEVELS = {'debug': logging.DEBUG,
          'info': logging.INFO,
          'warning': logging.WARNING,
          'error': logging.ERROR,
          'critical': logging.CRITICAL}

from storage import Storage
from http import HTTP

regex_at = re.compile(r'(?<!\\)\$[a-zA-Z]\w*')
regex_anything = re.compile(r'(?<!\\)\$anything')
regex_iter = re.compile(r'.*code=(?P<code>\d+)&ticket=(?P<ticket>.+).*')

params_default = Storage()
params = params_default

params.default_application = "init"
params.default_controller = "default"
params.default_function = "index"
params.routes_app = []
params.routes_in = []
params.routes_out = []
params.routes_onerror = []
params.routes_apps_raw = []
params.routes_logging = []
params.error_handler = None
params.error_message = '<html><body><h1>Invalid request</h1></body></html>'
params.error_message_custom = '<html><body><h1>%s</h1></body></html>'
params.error_message_ticket = \
    '<html><body><h1>Internal error</h1>Ticket issued: <a href="/admin/default/ticket/%(ticket)s" target="_blank">%(ticket)s</a></body><!-- this is junk text else IE does not display the page: '+('x'*512)+' //--></html>'

params_apps = dict()
params_base = Storage()
for key, value in params_default.items():
    params_base[key] = value
params = params_base

def compile_re(k, v):
    """
    Preprocess and compile the regular expressions in routes_app/in/out
    
    The resulting regex will match a pattern of the form:
    
        [remote address]:[protocol]://[host]:[method] [path]
    
    We allow abbreviated regexes on input; here we try to complete them.
    """
    k0 = k  # original k for error reporting
    # bracket regex in ^...$ if not already done
    if not k[0] == '^':
        k = '^%s' % k
    if not k[-1] == '$':
        k = '%s$' % k
    # if there are no :-separated parts, prepend a catch-all for the IP address
    if k.find(':') < 0:
        # k = '^.*?:%s' % k[1:]
        k = '^.*?:https?://[^:/]+:[a-z]+ %s' % k[1:]
    # if there's no ://, provide a catch-all for the protocol, host & method
    if k.find('://') < 0:
        i = k.find(':/')
        if i < 0:
            raise SyntaxError, "routes pattern syntax error: path needs leading '/' [%s]" % k0
        k = r'%s:https?://[^:/]+:[a-z]+ %s' % (k[:i], k[i+1:])
    # $anything -> ?P<anything>.*
    for item in regex_anything.findall(k):
        k = k.replace(item, '(?P<anything>.*)')
    # $a (etc) -> ?P<a>\w+
    for item in regex_at.findall(k):
        k = k.replace(item, r'(?P<%s>\w+)' % item[1:])
    # same for replacement pattern, but with \g
    for item in regex_at.findall(v):
        v = v.replace(item, r'\g<%s>' % item[1:])
    return (re.compile(k, re.DOTALL), v)

def load(routes='routes.py', app=None):
    """
    load: read and parse routes.py
    (called from main.py at web2py initialization time)
    store results in params 
    """
    global params, params_base
    symbols = {}

    if app is None:
        path = routes
    else:
        path = os.path.join('applications', app, routes)
    if not os.path.exists(path):
        return
    try:
        routesfp = open(path, 'r')
        exec routesfp.read() in symbols
        routesfp.close()
        logging.info('URL rewrite is on. configuration in %s' % path)
    except SyntaxError, e:
        routesfp.close()
        logging.error('Your %s has a syntax error ' % path + \
                          'Please fix it before you restart web2py\n' + \
                          traceback.format_exc())
        raise e

    p = Storage()
    for (sym, default) in params_default.items():
        p[sym] = default
    for sym in ('routes_app', 'routes_in', 'routes_out'):
        if sym in symbols:
            for (k, v) in symbols[sym]:
                p[sym].append(compile_re(k, v))
    for sym in ('routes_onerror', 'routes_apps_raw', 'routes_logging',
                'error_handler','error_message', 'error_message_ticket',
                'default_application','default_controller', 'default_function'):
        if sym in symbols:
            p[sym] = symbols[sym]
    if p.routes_logging:
        p.loglevel = LEVELS.get(p.routes_logging.lower(), logging.INFO)

    if app is None:
        params_base = p
        params = params_base
        for app in os.listdir('applications'):
            if os.path.exists(os.path.join('applications', app, routes)):
                load(routes, app)
    else:
        params_apps[app] = p

def filter_uri(e, regexes, tag, default=None):
    "filter incoming URI against a list of regexes"
    query = e.get('QUERY_STRING', None)
    path = e['PATH_INFO']
    host = e.get('HTTP_HOST', 'localhost').lower()
    original_uri = path + (query and '?'+query or '')
    i = host.find(':')
    if i > 0:
        host = host[:i]
    key = '%s:%s://%s:%s %s' % \
        (e['REMOTE_ADDR'],
         e.get('WSGI_URL_SCHEME', 'http').lower(), host,
         e.get('REQUEST_METHOD', 'get').lower(), path)
    for (regex, value) in regexes:
        if regex.match(key):
            rewritten = regex.sub(value, key)
            if params.routes_logging:
                logging.log(params.loglevel, '%s: [%s] [%s] -> %s' % (tag, key, value, rewritten))
            return (rewritten, query, original_uri)
    if params.routes_logging:
        logging.log(params.loglevel, '%s: [%s] -> %s (not rewritten)' % (tag, key, default))
    return (default, query, original_uri)

def select(e=None):
    """
    select a set of rewrite params for the current request
    called from main.wsgibase before any URL rewriting
    """
    global params
    params = params_base
    app = None
    if e and params.routes_app:
        (app, q, u) = filter_uri(e, params.routes_app, "routes_app")
        params = params_apps.get(app, params_base)
    return app  # for doctest

def filter_in(e):
    "called from main.wsgibase to rewrite incoming URL"
    if params.routes_in:
        (path, query, original_uri) = filter_uri(e, params.routes_in, "routes_in", e['PATH_INFO'])
        if path.find('?') < 0:
            e['PATH_INFO'] = path
        else:
            if query:
                path = path+'&'+query
            e['PATH_INFO'] = ''
            e['REQUEST_URI'] = path
            e['WEB2PY_ORIGINAL_URI'] = original_uri
    return e

def filter_out(url, e=None):
    "called from html.URL to rewrite outgoing URL"
    if params.routes_out:
        items = url.split('?', 1)
        if e:
            host = e.get('http_host', 'localhost').lower()
            i = host.find(':')
            if i > 0:
                host = host[:i]
            items[0] = '%s:%s://%s:%s %s' % \
                 (e.get('remote_addr', ''),
                  e.get('wsgi_url_scheme', 'http').lower(), host,
                  e.get('request_method', 'get').lower(), items[0])
        else:
            items[0] = ':http://localhost:get %s' % items[0]
        for (regex, value) in params.routes_out:
            if regex.match(items[0]):
                rewritten = '?'.join([regex.sub(value, items[0])] + items[1:])
                if params.routes_logging:
                    logging.log(params.loglevel, 'routes_out: [%s] -> %s' % (url, rewritten))
                return rewritten
    if params.routes_logging:
        logging.log(params.loglevel, 'routes_out: [%s] not rewritten' % url)
    return url


def try_redirect_on_error(http_object, request, ticket=None):
    "called from main.wsgibase to rewrite the http response"
    status = int(str(http_object.status).split()[0])
    if status>399 and params.routes_onerror:
        keys=set(('%s/%s' % (request.application, status),
                  '%s/*' % (request.application),
                  '*/%s' % (status),
                  '*/*'))
        for (key,redir) in params.routes_onerror:
            if key in keys:
                if redir == '!':
                    break
                elif '?' in redir:
                    url = redir + '&' + 'code=%s&ticket=%s&requested_uri=%s' % (status,ticket, request.env.request_uri)
                else:
                    url = redir + '?' + 'code=%s&ticket=%s&requested_uri=%s' % (status,ticket, request.env.request_uri)
                return HTTP(303,
                            'You are being redirected <a href="%s">here</a>' % url,
                            Location=url)
    return http_object

def filter_url(url, method='get', remote='0.0.0.0', out=False, app=False):
    "doctest interface to filter_in() and filter_out()"
    regex_url = re.compile(r'^(?P<scheme>http|https|HTTP|HTTPS)\://(?P<host>[^/]+)(?P<uri>\S*)')
    match = regex_url.match(url)
    scheme = match.group('scheme').lower()
    host = match.group('host').lower()
    uri = match.group('uri')
    k = uri.find('?')
    if k < 0:
        k = len(uri)
    (path_info, query_string) = (uri[:k], uri[k+1:])
    e = {
         'REMOTE_ADDR': remote,
         'REQUEST_METHOD': method,
         'WSGI_URL_SCHEME': scheme,
         'HTTP_HOST': host,
         'REQUEST_URI': uri,
         'PATH_INFO': path_info,
         'QUERY_STRING': query_string,
         #for filter_out request.env use lowercase
         'remote_addr': remote,
         'request_method': method,
         'wsgi_url_scheme': scheme,
         'http_host': host
    }
    if out:
        return filter_out(uri, e)
    elif app:
        return select(e)
    else:
        e = filter_in(e)
        if e.get('PATH_INFO','') == '':
            path = e['REQUEST_URI']
        elif query_string:
            path = e['PATH_INFO'] + '?' + query_string
        else:
            path = e['PATH_INFO']
    return scheme + '://' + host + path

def filter_err(status, application='app', ticket='tkt'):
    "doctest interface to routes_onerror"
    if status > 399 and params.routes_onerror:
        keys = set(('%s/%s' % (application, status),
                  '%s/*' % (application),
                  '*/%s' % (status),
                  '*/*'))
        for (key,redir) in params.routes_onerror:
            if key in keys:
                if redir == '!':
                    break
                elif '?' in redir:
                    url = redir + '&' + 'code=%s&ticket=%s' % (status,ticket)
                else:
                    url = redir + '?' + 'code=%s&ticket=%s' % (status,ticket)
                return url # redirection
    return status # no action
