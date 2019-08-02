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
