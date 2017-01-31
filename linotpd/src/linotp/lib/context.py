# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
'''establish a global context object'''


from linotp.lib.local import LocalContainer, release_local
from linotp.lib.error import ProgrammingError
from contextlib import contextmanager
from functools import partial

# --------------------------------------------------------------------------- --
# Context stack tracing
# --------------------------------------------------------------------------- --

# a security measure to avoid programming oversights, when working
# with thread locals and context managers

context_stack = LocalContainer(source_func=list)


@contextmanager
def context_stack_trace(manager_id, allow_nesting=True):

    """
    context_stack_trace is a contextmanager that is used to track usage
    of other context managers (such as request_context_safety). It pushes
    a manager_id onto a thread local stack in its entering block and pops
    it on exit.

    usage:

    @contextmanager
    def my_manager():
        with context_stack_trace('my_manager'):
            # do entering
            yield
            # do exiting

    This way you can check which context managers are active at the
    moment.

    To prevent accidental nesting of managers with the same id, you
    can set the parameter allow_nesting to False

    See also:
    :py:meth:`~linotp.lib.is_on_context_stack`
    """

    if not allow_nesting and manager_id in context_stack:
        raise ProgrammingError('Nesting of %s context managers is not allowed' %
                               manager_id)
    context_stack.append(manager_id)
    try:
        yield
    finally:
        popped_manager_id = context_stack.pop()
        if not popped_manager_id == manager_id:
            # this should not happen, when context stack is only accessed
            # through context_stack_trace. however, just in case someone
            # tempers with context_stack directly, we check for stack
            # consistency
            raise ProgrammingError('Misuse of context stack trace. Entered %s '
                                   'but exited %s' % manager_id,
                                   popped_manager_id)


def is_on_context_stack(manager_id):

    """
    returns, if we are inside a traced context manager with id manager_id.
    can be used to set access rights on some thread local variables, e.g.
    LocalContainer instances.

    :returns bool

    See also:

    :py:meth:`~linotp.lib.is_on_context_stack`
    """

    return manager_id in context_stack


# --------------------------------------------------------------------------- --
# request context
# --------------------------------------------------------------------------- --

    # replaces the old templ_context provided by pylons


request_context = LocalContainer(source_func=dict,
                                 access_check=partial(is_on_context_stack,
                                                      'request_context_safety'))


@contextmanager
def request_context_safety():

    """
    request_context_safety is a context managers that wraps the usage
    of request_context. to avoid data leakage through thread recycling
    we have to remove thread local data from request_context when the
    thread exits. the request_context_safety manager does that for you.

    linotp enforces this manager, so using request_context outside of
    request_context_safety will raise an exception.

    usage:

    with request_context_safety():
        # we can use request_context now, e.g.:
        request_context['config'] = getLinotpConfig
        # ...

    """

    with context_stack_trace('request_context_safety', allow_nesting=False):
        try:
            yield
        finally:
            release_local(request_context)
