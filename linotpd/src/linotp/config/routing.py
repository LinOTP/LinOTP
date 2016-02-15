# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#

"""Routes configuration

The more specific and detailed routes should be defined first so they
may take precedent over the more generic routes. For more information
refer to the routes manual at http://routes.groovie.org/docs/
"""

from pylons import config
from routes import Mapper


def make_map(global_conf, app_conf,):
    '''
    Create, configure and return the routes Mapper
    There are the three main controllers:
        /admin
        /validate
        /system
    '''
    routeMap = Mapper(directory=config['pylons.paths']['controllers'],
                      always_scan=config['debug'])
    routeMap.minimization = False

    # The ErrorController route (handles 404/500 error pages); it should
    # likely stay at the top, ensuring it can always be resolved

    routeMap.connect('/error/{action}', controller='error')
    routeMap.connect('/error/{action}/{id}', controller='error')

    # check if we are in migration mode -
    # ! this will disable most other controllers !
    migrate = app_conf.get('service.migrate', 'False') == 'True'

    # the first / - default will be taken!!
    # in case of selfservice, we route the default / to selfservice
    selfservice = app_conf.get('service.selfservice', 'True') == 'True'
    if selfservice and not migrate:
        routeMap.connect('/selfservice/custom-style.css',
                         controller='selfservice', action='custom_style')
        routeMap.connect('/selfservice', controller='selfservice', action='index')
        routeMap.connect('/', controller='selfservice', action='index')
        for cont in ['selfservice', 'account']:
            routeMap.connect('/%s/{action}' % cont, controller=cont)
            routeMap.connect('/%s/{action}/{id}' % cont, controller=cont)

    # in case of support for a remote selfservice, we have to enable this hook
    userservice = app_conf.get('service.userservice', 'True') == 'True'
    if userservice and not migrate:
        routeMap.connect('/userservice', controller='userservice', action='index')
        for cont in ['userservice']:
            routeMap.connect('/%s/{action}' % cont, controller=cont)
            routeMap.connect('/%s/{action}/{id}' % cont, controller=cont)

    # in case of manage, we route the default / to manage
    manage = app_conf.get('service.manage', 'True') == 'True'
    if manage and not migrate:
        routeMap.connect('/manage/custom-style.css', controller='manage', action='custom_style')
        routeMap.connect('/admin', controller='admin', action='show')
        routeMap.connect('/system', controller='system', action='getConfig')
        routeMap.connect('/manage/', controller='manage', action='index')
        routeMap.connect('/', controller='manage', action='index')

        for cont in ['admin', 'system', 'manage', 'audit', 'auth']:
            routeMap.connect('/%s/{action}' % cont, controller=cont)
            routeMap.connect('/%s/{action}/{id}' % cont, controller=cont)

    # in case of support for monitoring, we have to enable this hook
    monitoring = app_conf.get('service.monitoring', 'True') == 'True'
    if monitoring and not migrate:
        routeMap.connect('/monitoring', controller='monitoring', action='config')
        for cont in ['monitoring']:
            routeMap.connect('/%s/{action}' % cont, controller=cont)
            routeMap.connect('/%s/{action}/{id}' % cont, controller=cont)

    # in case of validate, we route the default / to validate
    validate = app_conf.get('service.validate', 'True') == 'True'
    if validate and not migrate:
        routeMap.connect('/validate', controller='validate', action='check')
        routeMap.connect('/', controller='validate', action='check')
        for cont in ['validate']:
            routeMap.connect('/%s/{action}' % cont, controller=cont)
            routeMap.connect('/%s/{action}/{id}' % cont, controller=cont)

    # ocra support
    ocra = app_conf.get('service.ocra', 'False') == 'True'
    if ocra and not migrate:
        routeMap.connect('/ocra', controller='ocra', action='checkstatus')
        for cont in ['ocra']:
            routeMap.connect('/%s/{action}' % cont, controller=cont)
            routeMap.connect('/%s/{action}/{id}' % cont, controller=cont)

    # openid support
    openid = app_conf.get('service.openid', 'False') == 'True'
    if openid and not migrate:
        # the default openid will be the status
        routeMap.connect('/openid/', controller='openid', action='status')
        for cont in ['openid']:
            routeMap.connect('/%s/{action}' % cont, controller=cont)
            routeMap.connect('/%s/{action}/{id}' % cont, controller=cont)

    # controller to get otp values
    # fallback for the getotp is the global linotpGetopt, but as all services
    # are in the app section, the app section one should be prefered
    getotp = (app_conf.get('service.getotp',
                           global_conf.get('linotpGetotp.active', 'False'))
              == 'True')
    if getotp and not migrate:
        for cont in ['gettoken']:
            routeMap.connect('/%s/{action}' % cont, controller=cont)
            routeMap.connect('/%s/{action}/{id}' % cont, controller=cont)

    # in case of u2f, we allow routes of type /u2f/realm/action
    u2f = app_conf.get('service.u2f', 'True') == 'True'
    if u2f and not migrate:
        for cont in ['u2f']:
            routeMap.connect('/%s/{realm}/{action}' % cont, controller=cont)
            routeMap.connect('/%s/{action}' % cont, controller=cont)

    # testing - for test setup: http sms provider callback
    self_test = app_conf.get('service.testing', 'False') == 'True'
    if self_test and not migrate:
        for cont in ['testing']:
            routeMap.connect('/%s/{action}' % cont, controller=cont)
            routeMap.connect('/%s/{action}/{id}' % cont, controller=cont)

    # linotp tools
    tools = global_conf.get('linotp.tools', 'True') == 'True'
    if tools and not migrate:
        for cont in ['tools']:
            routeMap.connect('/%s/{action}' % cont, controller = cont)
            routeMap.connect('/%s/{action}/{id}' % cont, controller=cont)

    if migrate:
        for cont in ['migrate']:
            routeMap.connect('/%s/{action}' % cont, controller=cont)
            routeMap.connect('/%s/{action}/{id}' % cont, controller=cont)

    return routeMap
