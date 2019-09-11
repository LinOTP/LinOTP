# Pylons-to-Flask porting scaffold.

import logging
import os.path

import webob
from werkzeug.datastructures import MultiDict

from pylons import (
    response, url, __version__,
)
from pylons.controllers.util import abort, forward, redirect
from pylons.middleware import (
    error_document_template,
)

from werkzeug import LocalProxy

import flask
from flask_mako import render_template, TemplateError

from .lib import helpers


log = logging.getLogger(__name__)

config = LocalProxy(lambda: flask.g.request_context['config'])

class RequestProxy(object):
    """
    Flask request object plus params -> args
    """
    def __init__(self, proxy):
        self.proxy = proxy

    @property
    def params(self):
        return self.proxy.args

    def __getattr__(self, name):
        return getattr(self.proxy, name)
request = RequestProxy(flask.request)

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
    def setdefault(self, key, value):
        return flask.g.request_context.setdefault(key, value)

tmpl_context = RequestContextProxy()

def set_config():
    """
    Set up config from flask request object
    """
    flask.g.request_context = {
        'config': {             # This must die, die, die!!!
            'linotp.root': os.path.dirname(os.path.abspath(__file__)),
            'pylons.h': helpers,  # This can probably go away
        },
    }

    # We get this from `load_environment()`, and it basically sucks.
    flask.g.request_context['config'].update(flask.current_app.config)

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


def render_mako(template_name, extra_context=None):
    """This is loosely compatible with the Pylons `render_mako()`
    function, so we don't need to change all the occurrences of this
    function elsewhere in the code. We try to avoid making *all* global
    variables available to Mako for replacement; in fact most
    templates only refer to the `c` variable, and we pass any additional
    ones in the `extra_context` parameter. Of course we still have
    all the stuff that *Flask* pushes into the template context, and
    eventually the templates may be rewritten to use that.
    """

    if extra_context:
        flask.g.request_context.update(extra_context)

    try:
        ret = render_template(template_name.lstrip('/'), c=tmpl_context, _=lambda s: s)
    except TemplateError as e:
        log.error(e.text)
        return e.text
    return ret
