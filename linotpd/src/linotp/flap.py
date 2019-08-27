# Pylons-to-Flask porting scaffold.

import webob
from webob.multidict import MultiDict, NestedMultiDict

from pylons import (
    config, request, response, tmpl_context, url,
    __version__,
)
from pylons.configuration import PylonsConfig as Config
from pylons.controllers import WSGIController
from pylons.controllers.util import abort, forward, redirect
from pylons.error import handle_mako_error
from pylons.middleware import (
    error_document_template, ErrorHandler, StatusCodeRedirect,
)
from pylons.templating import render_mako
from pylons.wsgiapp import PylonsApp as App

import flask


class ConfigProxy(object):
    """
    Flask configuration object
    """
    def __contains__(self, name):  # Make "... in config" work
        return name in flask.g.request_context['config']
    def __getitem__(self, name):
        return flask.g.request_context['config'].__getitem__(name)
    def get(self, name, default=None):
        return flask.g.request_context['config'].get(name, default)
config = ConfigProxy()

class RequestContextProxy(object):
    def __getattr__(self, name):
        return flask.g.request_context.__getitem__(name)
    def get(self, name, default=None):
        return flask.g.request_context.get(name, default)
        #return flask.g.request_context.__getattribute__(name)
    def __setattr__(self, name, value):
        #flask.g.request_context.__setattr__(name, value)
        flask.g.request_context.__setitem__(name, value)
    def __getitem__(self, key):
        return flask.g.request_context.__getitem__(key)
    def __setitem__(self, key, value):
        flask.g.request_context.__setitem__(key, value)

tmpl_context = RequestContextProxy()

def set_config():
    """
    Set up config from flask request object
    """
    flask.g.request_context = {
        'config': {},
    }

def _(s):
    """Mickey Mouse translation utility."""
    return s


def set_lang(*args, **kwargs):
    pass


class LanguageError(Exception):
    pass


class HTTPUnauthorized(webob.exc.HTTPUnauthorized):
    pass

class HTTPForbidden(webob.exc.HTTPForbidden):
    pass
