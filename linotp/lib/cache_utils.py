#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
#
#    This file is part of LinOTP server.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""
This module contains helper functions for
caching
"""

import functools
import logging

from linotp.lib.context import request_context

log = logging.getLogger(__name__)


def cache_in_request(
    _func=None,
    *,
    key_generator=lambda *args, **kwargs: args + tuple(kwargs.items()),
):
    """Decorator to use for caching function calls in the request context

    This decorator can be used to cache the function calls within the
    context of a request

    :param key_generator: the function which takes exactly the same arguments
    as the function being cached and returns a unique key for its output
    when the key_generator is not passed, it will use args+tuple(kwargs.items())
    as the key.
    This can obviously fail if the args are not hashable.
    The key can be any object which is allowed
    to be used as the key of a dictionary.


    :return: the cached output of the decorated function
    or the output of a new call to the decorated function

    :Note: In case of an optional key_generator, it can be fatal if
    the generated keys are not unique for each functional call


    :example:

    >>>@cache_in_request
       func_to_be_decorated(*args, **kwargs)
    >>>def key_generator_for_func_to_be_decorated(*foo, **bar): lambda ....
       @cache_in_request(key_generator=key_generator_for_func_to_be_decorated)
       def func_to_be_decorated(*foo, **bar)

    """

    def cache_in_request_decorator(func_to_cache):
        @functools.wraps(func_to_cache)
        def request_cacher(*args, **kwargs):
            cache_name = func_to_cache.__name__ + "_cache"
            functions_cache: dict = request_context.setdefault(cache_name, {})

            cache_key = f"{key_generator(*args, **kwargs)}"

            log_prefix = f"[{func_to_cache.__name__}]"
            if result := functions_cache.get(cache_key):
                log.debug("%s: output values already in cache", log_prefix)
                return result

            log.debug("%s: output values not in cache", log_prefix)
            result = func_to_cache(*args, **kwargs)
            functions_cache[cache_key] = result
            return result

        return request_cacher

    if _func is None:
        return cache_in_request_decorator
    else:
        return cache_in_request_decorator(_func)
