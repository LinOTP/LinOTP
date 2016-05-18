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

"""
manage controller - In provides the web gui management interface
"""

import os

try:
    import json
except ImportError:
    import simplejson as json

from pylons import request, response, config, tmpl_context as c
from linotp.lib.base import BaseController
from pylons.templating import render_mako as render
from mako.exceptions import CompileException

from paste.deploy.converters import asbool

# Our Token stuff
from linotp.lib.token   import TokenIterator
from linotp.lib.token   import getTokenType
from linotp.lib.token   import newToken


from linotp.lib.user    import getUserFromParam, getUserFromRequest
from linotp.lib.user    import getUserList, User

from linotp.lib.util    import getParam
from linotp.lib.util    import check_session
from linotp.lib.util    import get_version
from linotp.lib.util    import get_copyright_info
from linotp.lib.reply   import sendError

from linotp.lib.util    import remove_empty_lines
from linotp.lib.util import get_client
from linotp.lib.util import unicode_compare
from linotp.model.meta import Session

from linotp.lib.policy import checkPolicyPre, PolicyException, getAdminPolicies, getPolicyDefinitions

from pylons.i18n.translation import _

audit = config.get('audit')

import logging

log = logging.getLogger(__name__)

from linotp.lib.ImportOTP import getKnownTypes, getImportText
KNOWN_TYPES = getKnownTypes()
IMPORT_TEXT = getImportText()
log.info("importing linotp.lib. Known import types: %s" % IMPORT_TEXT)


optional = True
required = False

class ManageController(BaseController):

    def __before__(self, action, **params):

        log.debug("[__before__::%r] %r" % (action, params))

        try:
            audit.initialize()
            c.audit['success'] = False
            c.audit['client'] = get_client()

            c.version = get_version()
            c.licenseinfo = get_copyright_info()
            c.polDefs = getPolicyDefinitions()

            # Session handling for the functions, that show data:
            # Also exclude custom-style.css, since the CSRF check
            # will always fail and return a HTTP 401 anyway.
            # A HTTP 404 makes more sense.
            if request.path.lower() in ['/manage/', '/manage',
                                        '/manage/logout',
                                        '/manage/audittrail',
                                        '/manage/policies',
                                        '/manage/tokenview',
                                        '/manage/userview',
                                        '/manage/help',
                                        '/manage/custom-style.css']:
                pass
            else:
                check_session()

        except Exception as exx:
            log.exception("[__before__::%r] exception %r" % (action, exx))
            Session.rollback()
            Session.close()
            return sendError(response, exx, context='before')

        finally:
            log.debug("[__before__::%r] done" % (action))

    def __after__(self):

        if c.audit['action'] in [ 'manage/tokenview_flexi',
                                'manage/userview_flexi' ]:
            c.audit['administrator'] = getUserFromRequest(request).get("login")
            if request.params.has_key('serial'):
                    c.audit['serial'] = request.params['serial']
                    c.audit['token_type'] = getTokenType(request.params['serial'])

            audit.log(c.audit)


    def index(self):
        '''
        This is the main function of the management web UI
        '''

        try:
            c.debug = asbool(config.get('debug', False))
            c.title = "LinOTP Management"
            admin_user = getUserFromRequest(request)
            if admin_user.has_key('login'):
                c.admin = admin_user['login']

            log.debug("[index] importers: %s" % IMPORT_TEXT)
            c.importers = IMPORT_TEXT
            c.help_url = config.get('help_url')

            ## add render info for token type config
            confs = _getTokenTypeConfig('config')
            token_config_tab = {}
            token_config_div = {}
            for conf in confs:
                tab = ''
                div = ''
                try:
                    #loc = conf +'_token_settings'
                    tab = confs.get(conf).get('title')
                    #tab = '<li ><a href=#'+loc+'>'+tab+'</a></li>'

                    div = confs.get(conf).get('html')
                    #div = +div+'</div>'
                except Exception as e:
                    log.debug('[index] no config info for token type %s  (%r)' % (conf, e))

                if tab is not None and div is not None and len(tab) > 0 and len(div) > 0:
                    token_config_tab[conf] = tab
                    token_config_div[conf] = div

            c.token_config_tab = token_config_tab
            c.token_config_div = token_config_div

            ##  add the enrollment fragments from the token definition
            ##  tab: <option value="ocra">${_("OCRA - challenge/response Token")}</option>
            ##  div: "<div id='"+ tt + "'>"+enroll+"</div>"
            enrolls = _getTokenTypeConfig('init')

            token_enroll_tab = {}
            token_enroll_div = {}
            for conf in enrolls:
                tab = ''
                div = ''
                try:
                    tab = enrolls.get(conf).get('title')
                    div = enrolls.get(conf).get('html')
                except Exception as e:
                    log.debug('[index] no enrollment info for token type %s  (%r)' % (conf, e))

                if tab is not None and div is not None and len(tab) > 0 and len(div) > 0:
                    token_enroll_tab[conf] = tab
                    token_enroll_div[conf] = div

            c.token_enroll_tab = token_enroll_tab
            c.token_enroll_div = token_enroll_div

            c.tokentypes = _getTokenTypes()

            http_host = request.environ.get("HTTP_HOST")
            url_scheme = request.environ.get("wsgi.url_scheme")
            c.logout_url = "%s://log-me-out:fake@%s/manage/logout" % (url_scheme, http_host)

            Session.commit()
            ren = render('/manage/manage-base.mako')
            return ren

        except PolicyException as pe:
            log.exception("[index] Error during checking policies: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as ex:
            log.exception("[index] failed! %r" % ex)
            Session.rollback()
            return sendError(response, ex)

        finally:
            Session.close()
            log.debug('[index] done')


    def tokentype(self):
        '''
        '''
        c.title = 'TokenTypeInfo'
        g = config['pylons.app_globals']
        tokens = g.tokenclasses
        ttinfo = []
        ttinfo.extend(tokens.keys())
        for tok in tokens:
            tclass = tokens.get(tok)
            tclass_object = newToken(tclass)
            if hasattr(tclass_object, 'getClassType'):
                ii = tclass_object.getClassType()
                ttinfo.append(ii)

        log.debug("[index] importers: %s" % IMPORT_TEXT)
        c.tokeninfo = ttinfo

        return render('/manage/tokentypeinfo.mako')


    def policies(self):
        '''
        This is the template for the policies TAB
        '''
        c.title = "LinOTP Management - Policies"
        return render('/manage/policies.mako')


    def audittrail(self):
        '''
        This is the template for the audit trail TAB
        '''
        c.title = "LinOTP Management - Audit Trail"
        return render('/manage/audit.mako')


    def tokenview(self):
        '''
        This is the template for the token TAB
        '''
        c.title = "LinOTP Management"
        c.tokenArray = []
        return render('/manage/tokenview.mako')


    def userview(self):
        '''
        This is the template for the token TAB
        '''
        c.title = "LinOTP Management"
        c.tokenArray = []
        return render('/manage/userview.mako')

    def custom_style(self):
        '''
        If this action was called, the user hasn't created a custom-style.css yet. To avoid hitting
        the debug console over and over, we serve an empty file.
        '''
        response.headers['Content-type'] = 'text/css'
        return ''

    def _flexi_error(self, error):
        return json.dumps({ "page": 1,
                "total": 1,
                "rows": [
                 { 'id' : 'error',
                    'cell' : ['E r r o r', error,
                    '', '', '', '', '', ''
                 ] } ] }
                , indent=3)


    def tokenview_flexi(self):
        '''
        This function is used to fill the flexigrid.
        Unlike the complex /admin/show function, it only returns a
        simple array of the tokens.
        '''
        param = request.params

        try:
            #serial  = getParam(param,"serial",optional)
            c.page = getParam(param, "page", optional)
            c.filter = getParam(param, "query", optional)
            c.qtype = getParam(param, "qtype", optional)
            c.sort = getParam(param, "sortname", optional)
            c.dir = getParam(param, "sortorder", optional)
            c.psize = getParam(param, "rp", optional)

            filter_all = None
            filter_realm = None
            user = User()

            if c.qtype == "loginname":
                if "@" in c.filter:
                    (login, realm) = c.filter.split("@")
                    user = User(login, realm)
                else:
                    user = User(c.filter)

            elif c.qtype == "all":
                filter_all = c.filter
            elif c.qtype == "realm":
                filter_realm = c.filter

            # check admin authorization
            res = checkPolicyPre('admin', 'show', param , user=user)

            filterRealm = res['realms']
            # check if policies are active at all
            # If they are not active, we are allowed to SHOW any tokens.
            pol = getAdminPolicies("show")
            # If there are no admin policies, we are allowed to see all realms
            if not pol['active']:
                filterRealm = ["*"]

            # check if we only want to see ONE realm or see all realms we are allowerd to see.
            if filter_realm:
                if filter_realm in filterRealm or '*' in filterRealm:
                    filterRealm = [filter_realm]

            log.debug("[tokenview_flexi] admin >%s< may display the following realms: %s" % (pol['admin'], pol['realms']))
            log.debug("[tokenview_flexi] page: %s, filter: %s, sort: %s, dir: %s" % (c.page, c.filter, c.sort, c.dir))

            if c.page is None:
                c.page = 1
            if c.psize is None:
                c.psize = 20

            log.debug("[tokenview_flexi] calling TokenIterator for user=%s@%s, filter=%s, filterRealm=%s"
                        % (user.login, user.realm, filter_all, filterRealm))
            c.tokenArray = TokenIterator(user, None, c.page , c.psize, filter_all, c.sort, c.dir, filterRealm=filterRealm)
            c.resultset = c.tokenArray.getResultSetInfo()
            # If we have chosen a page to big!
            lines = []
            for tok in c.tokenArray:
                lines.append(
                    { 'id' : tok['LinOtp.TokenSerialnumber'],
                        'cell': [
                            tok['LinOtp.TokenSerialnumber'],
                            tok['LinOtp.Isactive'],
                            tok['User.username'],
                            tok['LinOtp.RealmNames'],
                            tok['LinOtp.TokenType'],
                            tok['LinOtp.FailCount'],
                            tok['LinOtp.TokenDesc'],
                            tok['LinOtp.MaxFail'],
                            tok['LinOtp.OtpLen'],
                            tok['LinOtp.CountWindow'],
                            tok['LinOtp.SyncWindow'],
                            tok['LinOtp.Userid'],
                            tok['LinOtp.IdResClass'], ]
                    }
                    )

            # We need to return 'page', 'total', 'rows'
            response.content_type = 'application/json'
            res = { "page": int(c.page),
                "total": c.resultset['tokens'],
                "rows": lines }

            c.audit['success'] = True

            Session.commit()
            return json.dumps(res, indent=3)

        except PolicyException as pe:
            log.exception("[tokenview_flexi] Error during checking policies: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[tokenview_flexi] failed: %r" % e)
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()
            log.debug("[tokenview_flexi] done")


    def userview_flexi(self):
        '''
        This function is used to fill the flexigrid.
        Unlike the complex /admin/userlist function, it only returns a
        simple array of the tokens.
        '''
        param = request.params

        try:
            #serial  = getParam(param,"serial",optional)
            c.page = getParam(param, "page", optional)
            c.filter = getParam(param, "query", optional)
            qtype = getParam(param, "qtype", optional)
            c.sort = getParam(param, "sortname", optional)
            c.dir = getParam(param, "sortorder", optional)
            c.psize = getParam(param, "rp", optional)
            c.realm = getParam(param, "realm", optional)

            user = getUserFromParam(param, optional)
            # check admin authorization
            # check if we got a realm or resolver, that is ok!
            checkPolicyPre('admin', 'userlist', { 'user': user.login,
                                                 'realm' : c.realm })

            if c.filter == "":
                c.filter = "*"

            log.debug("[userview_flexi] page: %s, filter: %s, sort: %s, dir: %s"
                      % (c.page, c.filter, c.sort, c.dir))

            if c.page is None:
                c.page = 1
            if c.psize is None:
                c.psize = 20

            c.userArray = getUserList({ qtype:c.filter,
                                       'realm':c.realm }, user)
            c.userNum = len(c.userArray)

            lines = []
            for u in c.userArray:
                # shorten the useridresolver, to get a better display value
                resolver_display = ""
                if "useridresolver" in u:
                    if len(u['useridresolver'].split(".")) > 3:
                        resolver_display = u['useridresolver'].split(".")[3] + " (" + u['useridresolver'].split(".")[1] + ")"
                    else:
                        resolver_display = u['useridresolver']
                lines.append(
                    { 'id' : u['username'],
                        'cell': [
                            (u['username']) if u.has_key('username') else (""),
                            (resolver_display),
                            (u['surname']) if u.has_key('surname') else (""),
                            (u['givenname']) if u.has_key('givenname') else (""),
                            (u['email']) if u.has_key('email') else (""),
                            (u['mobile']) if u.has_key('mobile') else (""),
                            (u['phone']) if u.has_key('phone') else (""),
                            (u['userid']) if u.has_key('userid') else (""),
                             ]
                    }
                    )

            # sorting
            reverse = False
            sortnames = { 'username' : 0, 'useridresolver' : 1,
                    'surname' : 2, 'givenname' : 3, 'email' : 4,
                    'mobile' :5, 'phone' : 6, 'userid' : 7 }
            if c.dir == "desc":
                reverse = True

            lines = sorted(lines,
                           key=lambda user: user['cell'][sortnames[c.sort]],
                           reverse=reverse,
                           cmp=unicode_compare)
            # end: sorting

            # reducing the page
            if c.page and c.psize:
                page = int(c.page)
                psize = int(c.psize)
                start = psize * (page - 1)
                end = start + psize
                lines = lines[start:end]

            # We need to return 'page', 'total', 'rows'
            response.content_type = 'application/json'
            res = { "page": int(c.page),
                "total": c.userNum,
                "rows": lines }

            c.audit['success'] = True

            Session.commit()
            return json.dumps(res, indent=3)

        except PolicyException as pe:
            log.exception("[userview_flexi] Error during checking policies: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[userview_flexi] failed: %r" % e)
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()
            log.debug('[userview_flexi] done')


    def tokeninfo(self):
        '''
        this returns the contents of /admin/show?serial=xyz in an html format
        '''
        param = request.params

        try:
            serial = getParam(param, 'serial', required)

            filterRealm = ""
            # check admin authorization
            res = checkPolicyPre('admin', 'show', param)

            # check if policies are active at all
            # If they are not active, we are allowed to SHOW any tokens.
            filterRealm = ["*"]
            if res['active'] and res['realms']:
                filterRealm = res['realms']

            log.info("[tokeninfo] admin >%s< may display the following realms:"
                     " %s" % (res['admin'], filterRealm))
            log.info("[tokeninfo] displaying tokens: serial: %s", serial)

            toks = TokenIterator(User("", "", ""), serial,
                                 filterRealm=filterRealm)

            # now row by row
            lines = []
            for tok in toks:
                lines.append(tok)
            if len(lines) > 0:
                c.tokeninfo = lines[0]
            else:
                c.tokeninfo = {}

            for k in c.tokeninfo:
                if "LinOtp.TokenInfo" == k:
                    try:
                        # Try to convert string to Dictionary
                        c.tokeninfo['LinOtp.TokenInfo'] = json.loads(
                                            c.tokeninfo['LinOtp.TokenInfo'])
                    except:
                        pass

            return render('/manage/tokeninfo.mako')

        except PolicyException as pe:
            log.exception("[tokeninfo] Error during checking policies: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[tokeninfo] failed! %r" % e)
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()
            log.debug('[tokeninfo] done')


    def logout(self):
        '''
        redirect logout
        '''
        from pylons.controllers.util import redirect
        http_host = request.environ.get("HTTP_HOST")
        url_scheme = request.environ.get("wsgi.url_scheme", "https")
        redirect("%s://%s/manage/" % (url_scheme, http_host))


    def help(self):
        '''
        This downloads the Manual

        The filename will be the 3. part,ID
        https://172.16.200.6/manage/help/somehelp.pdf
        The file is downloaded through pylons!

        '''

        try:
            directory = config.get("linotpManual.Directory", "/usr/share/doc/linotp")
            default_filename = config.get("linotpManual.File", "LinOTP_Manual-en.pdf")
            headers = []

            route_dict = request.environ.get('pylons.routes_dict')
            filename = route_dict.get('id')
            if not filename:
                filename = default_filename + ".gz"
                headers = [('content-Disposition', 'attachment; filename=\"' + default_filename + '\"'),
                           ('content-Type', 'application/x-gzip')
                           ]

            from paste.fileapp import FileApp
            wsgi_app = FileApp("%s/%s" % (directory, filename), headers=headers)
            Session.commit()
            return wsgi_app(request.environ, self.start_response)

        except Exception as e:
            log.exception("[help] Error loading helpfile: %r" % e)
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()
            log.debug("[help] done")




############################################################
def _getTokenTypes():
    '''
        _getTokenTypes - retrieve the list of dynamic tokens and their title section

        :return: dict with token type and title
        :rtype:  dict
    '''

    glo = config['pylons.app_globals']
    tokenclasses = glo.tokenclasses

    tokens = []
    tokens.extend(tokenclasses.keys())

    tinfo = {}
    for tok in tokens:
        if tok in tokenclasses.keys():
            tclass = tokenclasses.get(tok)
            tclass_object = newToken(tclass)
            if hasattr(tclass_object, 'getClassInfo'):
                ii = tclass_object.getClassInfo('title') or tok
                tinfo[tok] = _(ii)

    return tinfo


def _getTokenTypeConfig(section='config'):
    '''
        _getTokenTypeConfig - retrieve from the dynamic token the
                            tokentype section, eg. config or enroll

        :param section: the section of the tokentypeconfig
        :type  section: string

        :return: dict with tab and page definition (rendered)
        :rtype:  dict
    '''

    res = {}
    g = config['pylons.app_globals']
    tokenclasses = g.tokenclasses

    for tok in tokenclasses.keys():
        tclass = tokenclasses.get(tok)
        tclass_object = newToken(tclass)
        if hasattr(tclass_object, 'getClassInfo'):

            conf = tclass_object.getClassInfo(section, ret={})

            ## set globale render scope, so that the mako
            ## renderer will return only a subsection from the template
            p_html = ''
            t_html = ''
            try:
                page = conf.get('page')
                c.scope = page.get('scope')
                p_html = render(os.path.sep + page.get('html'))
                p_html = remove_empty_lines(p_html)


                tab = conf.get('title')
                c.scope = tab.get('scope')
                t_html = render(os.path.sep + tab.get('html'))
                t_html = remove_empty_lines(t_html)

            except CompileException as ex:
                log.exception("[_getTokenTypeConfig] compile error while processing %r.%r:" % (tok, section))
                log.error("[_getTokenTypeConfig] %r" % ex)
                raise Exception(ex)

            except Exception as e:
                log.debug('no config for token type %r (%r)' % (tok, e))
                p_html = ''

            if len (p_html) > 0:
                res[tok] = { 'html' : p_html, 'title' : t_html}

    return res

############################################################

