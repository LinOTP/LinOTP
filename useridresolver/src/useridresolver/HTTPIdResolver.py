# -*- coding: utf-8 -*-

#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
#
#    This file is part of LinOTP userid resolvers.
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
This module implements the UserIdResolver to access an user store via
http and json

Dependencies: UserIdResolver
"""

#from sqlalchemy.event import listen

from . import resolver_registry
from useridresolver.UserIdResolver import UserIdResolver

import json

import logging
log = logging.getLogger(__name__)

DEFAULT_ENCODING = "utf-8"


import urllib2
import urllib
import base64


def urllib_encoded_dict(in_dict):
    """
    urllib requires the parameters to be in UTF-8

    :param in_dict: the incomming dictionary
    :return: return a UTF-8 encoded dictionary
    """

    out_dict = {}
    for k, v in in_dict.iteritems():
        if type(v) in [str, unicode]:
            v = v.encode('utf8')
        out_dict[k] = v
    return out_dict


def urllib_request(url, parameter,
                   username=None, password=None, method='POST',
                   config=None, timeout=10.0):
    """
    build the urllib request and check the response for success or fail

    :param url: target url
    :param parameter: additonal parameter to append to the url request
    :param username: basic authentication with username (optional)
    :param password: basic authentication with password (optional)
    :param method: run an GET or POST request
    :param config: in case of Proxy support, the proxy settings are taken from
    :param timeout: timeout for waiting on connect/reply

    :return: the response of the request
    """
    try:

        handlers = []
        if config and 'PROXY' in config and config['PROXY']:
            # for simplicity we set both protocols
            proxy_handler = urllib2.ProxyHandler({"http": config['PROXY'],
                                                  "https": config['PROXY']})
            handlers.append(proxy_handler)
            print "using Proxy: %r" % config['PROXY']

        if username and password is not None:
            password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
            password_mgr.add_password(None, url, username, password)
            auth_handler = urllib2.HTTPBasicAuthHandler(password_mgr)
            handlers.append(auth_handler)

        opener = urllib2.build_opener(*handlers)
        urllib2.install_opener(opener)

        full_url = str(url)
        encoded_params = None
        if parameter is not None and len(parameter) > 0:
            encoded_params = urllib.urlencode(urllib_encoded_dict(parameter))

        if method == 'GET':
            c_data = None
            if encoded_params:
                full_url = str("%s?%s" % (url, encoded_params))
        else:
            c_data = encoded_params

        requ = urllib2.Request(full_url, data=c_data, headers={})
        if username and password is not None:
            base64string = base64.encodestring('%s:%s' %
                                    (username, password)).replace('\n', '')
            requ.add_header("Authorization", "Basic %s" % base64string)

        response = urllib2.urlopen(requ, timeout=float(timeout))
        reply = response.read()

        log.debug(">>%s...%s<<", reply[:20], reply[-20:])

    except Exception as exc:
        log.exception("%r" % exc)
        raise Exception("Failed to send request: %r" % exc)

    return reply


@resolver_registry.class_entry('useridresolver.HTTPIdResolver.IdResolver')
@resolver_registry.class_entry('useridresolveree.HTTPIdResolver.IdResolver')
@resolver_registry.class_entry('useridresolver.httpresolver')
@resolver_registry.class_entry('httpresolver')
class IdResolver (UserIdResolver):

    @classmethod
    def setup(cls, config=None, cache_dir=None):
        '''
        this setup hook is triggered, when the server
        starts to serve the first request

        :param config: the linotp config
        :type  config: the linotp config dict
        '''
        _config = config
        _cache_dir = cache_dir

        log.info("Setting up the HTTTPResolver")
        return

    @staticmethod
    def testconnection(params):
        '''
        test the http connection - with a POST request on the userlist

        dict: { 'timeout': u'5',
                'type': u'http',

                'password': u'Test123!',
                'authuser': u'admin',
                'certificate': u' ',
                'resolvername': u'dadas',
                'uri': u'http://127.0.0.1:5001',

                'userlist_request_path': u'/admin/userlist',
                'userlist_result_path': u'/result/value',
                'userlist_request_mapping': u'{"username":"{USERNAME}",
                                               "page":"{PAGE}"}',
                'userlist_result_mapping': u'{}',

                'userid_result_mapping': u'{}',
                'userid_request_path': u'/admin/userlist',
                'userid_request_mapping': u'{"userid":"{USERID}",
                                             "page":"{PAGE}"}',
                'userid_result_path': u'/result/value',

                'username_request_mapping': u'{"username":"{USERNAME}",
                                               "page":"{PAGE}"}'
                'username_request_path': u'/admin/userlist'}
                'username_result_path': u'/result/value',
                'username_result_mapping': u'{}',

        '''
        result = ''
        log.info("Setting up the HTTPResolver")
        try:
            uri = params.get('uri', '').split(',')[0]

            authuser = params.get('authuser')
            password = params.get('password')
            certificate = params.get('certificate')

            timeout = float(params.get('timeout', 0.1))

            result_path = params.get('userlist_result_path', '')
            result_mapping = params.get('userlist_result_mapping', '{}')

            request_path = params.get('userlist_request_path', '')
            request_mapping = params.get('userlist_request_mapping', '{}')

            # now prepare the query attributes
            request_params = {'{USERNAME}': '*',
                        '{PAGE}': '1',
                        '{PAGESIZE}': '10'
                        }

            credentials = {'user': authuser,
                           'password': password,
                           'certificate': certificate}
            result = ""

            try:
                result = IdResolver._do_request(uri, timeout, credentials,
                                request_path, request_mapping, request_params,
                                result_path, result_mapping)

                status = "success"

            except Exception as exx:
                status = "error"
                result = "%r" % exx

            return (status, result)

        except Exception as exx:
            result = "%r" % exx
            status = "error"
            log.error("Error %r" % exx)
            return (status, result)

    @staticmethod
    def _do_request(uri, timeout, credentials,
                    request_path, request_mapping, request_params,
                    result_path, result_mapping):

            query_params = json.loads(request_mapping)
            for key, value in query_params.items():
                for repl, repl_val in request_params.items():
                    if repl in value:
                        value = value.replace(repl, repl_val)
                query_params[key] = value

            url = "%s/%s" % (uri.strip('/'), request_path.lstrip('/'))
            response = urllib_request(url, query_params,
                                      credentials.get('user'),
                                      credentials.get('password'),
                                      timeout=timeout)

            result_data = json.loads(response)

            result_pathes = result_path.strip('/').split('/')
            result_mappings = json.loads(result_mapping)

            for path in result_pathes:
                result_data = result_data.get(path, {})
            result = result_data
            result = IdResolver._map_result(result_mappings, result)

            return result

    @staticmethod
    def _map_result(mapping, result):
        """
        helper method to map the result to something linotp can handle
        """

        if type(mapping) != dict:
            return result

        if type(result) != list:
            return result

        # we have to invert the mapping
        re_map = {}
        for key, value in mapping.items():
            re_map[value] = key

        if not(re_map):
            return result

        re_list = []
        for entry in result:
            if type(entry) not in (dict):
                continue

            res_entry = {}
            for key, value in entry.items():
                if key in re_map:
                    res_entry[re_map[key]] = value
            re_list.append(res_entry)

        return re_list

    def __init__(self):
        self.base_url = None
        self.conf = None
        self.config = None

    def close(self):
        return

    def getResolverId(self):
        """
        getResolverId - provide the resolver identifier

        :return: returns the resolver identifier string
                 or empty string if not exist
        :rtype : string
        """
        resolver = "HTTPIdResolver.IdResolver"
        if self.conf:
            resolver = resolver + "." + self.conf
        return resolver

    def checkPass(self, uid, password):
        '''
        checkPass - checks the password for a given uid.

        :param uid: userid to be checked
        :type  uid: string
        :param password: user password
        :type  password: string

        :return :  true in case of success, false if password does not match
        :rtype :   boolean

        :todo: extend to support htpasswd passwords:
             http://httpd.apache.org/docs/2.2/misc/password_encryptions.html
        '''
        _password = password
        log.info("[checkPass] checking password for user %s" % uid)
        log.error("[checkPass] password is currently not defined in HTTP"
                  " mapping!")

        return False

    @classmethod
    def getResolverClassType(cls):
        return 'httpresolver'

    def getResolverType(self):
        '''
        getResolverType - return the type of the resolver

        :return: returns the string 'sqlresolver'
        :rtype:  string
        '''
        return IdResolver.getResolverClassType()

    @classmethod
    def getResolverClassDescriptor(cls):
        '''
        return the descriptor of the resolver, which is
        - the class name and
        - the config description

        :return: resolver description dict
        :rtype:  dict
        TODO: adjust

        '''
        descriptor = {}
        typ = cls.getResolverClassType()
        descriptor['clazz'] = "useridresolver.HTTPIdResolver.IdResolver"
        descriptor['config'] = {
                                'BASEURL': 'string',
                                'userQuery': 'string',
                                'userIdQuery': 'string',
                                'User': 'string',
                                'Password': 'password',
                                 }
        return {typ: descriptor}

    def getResolverDescriptor(self):
        return IdResolver.getResolverClassDescriptor()

    def _get_my_config(self, config, conf):
        """
        extract only those resolver entries, which are meant for me :-)
        """
        my_config = {}
        for key, value in config.items():
            parts = key.split('.')
            if parts[-1] == conf and parts[1] == 'httpresolver':
                new_key = ".".join(parts[2:-1])
                my_config[new_key.lower()] = value
        return my_config

    def loadConfig(self, config, conf=""):
        '''
        loadConfig - load the config for the resolver

        :param config: configuration for the sqlresolver
        :type  config: dict
        :param conf: configuration postfix
        :type  conf: string
        '''
        log.debug("[loadConfig]")
        self.conf = conf
        self.config = self._get_my_config(config, conf)

        log.debug("[loadConfig] done")
        return self

    def checkMapping(self):
        """
        check the given sql field map against the sql table definition

        :return: -
        """
        log.debug("[checkMapping]")

        log.debug('[checkMapping] done')
        return

    def getUserId(self, loginName):
        '''
        return the userId which mappes to a loginname

        :param loginName: login name of the user
        :type loginName:  string

        :return: userid - unique idenitfier for this unser
        :rtype:  string
        '''

        try:
            uri = self.config['uri']
            timeout = self.config['timeout']

            username = self.config['authuser']
            password = self.config['password']
            certificate = self.config['certificate']

            credentials = {'user': username,
                           'password': password,
                           'certificate': certificate}

            # now prepare the query attributes
            request_params = {'{USERNAME}': loginName,
                        '{PAGE}': '0',
                        '{PAGESIZE}': '10'
                        }

            request_path = self.config['userid_request_path']
            request_mapping = self.config['userid_request_mapping']
            result_path = self.config['userid_result_path']
            result_mapping = self.config['userid_result_mapping']

            results = IdResolver._do_request(uri, timeout, credentials,
                            request_path, request_mapping, request_params,
                            result_path, result_mapping)

            result = results[0]
            userId = result.get('userid')
            return userId

        except Exception as exx:
            result = "%r" % exx
            raise exx

    def getUsername(self, userId):
        '''
        get the loginname from the given userid

        :param userId: userid descriptor
        :type userId: string

        :return: loginname
        :rtype:  string
        '''
        log.debug("%s" % userId)
        result = self.getUserInfo(userId)
        username = result.get('username')
        return username

    def getUserInfo(self, userId):
        '''
            return all user related information

            @param userId: specied user
            @type userId:  string
            @return: dictionary, containing all user related info
            @rtype:  dict

        '''
        log.debug("[getUserInfo] %s[%s]" % (userId, type(userId)))
        try:
            uri = self.config['uri']
            timeout = self.config['timeout']

            username = self.config['authuser']
            password = self.config['password']
            certificate = self.config['certificate']

            credentials = {'user': username,
                           'password': password,
                           'certificate': certificate}

            # now prepare the query attributes
            request_params = {'{USERID}': userId,
                        '{PAGE}': '0',
                        '{PAGESIZE}': '10'
                        }

            request_path = self.config['username_request_path']
            request_mapping = self.config['username_request_mapping']
            result_path = self.config['username_result_path']
            result_mapping = self.config['username_result_mapping']

            result = IdResolver._do_request(uri, timeout, credentials,
                            request_path, request_mapping, request_params,
                            result_path, result_mapping)

            log.debug('[getUsername] done')
            return result[0]

        except Exception as exx:
            result = "%r" % exx
            raise exx

        finally:
            log.debug('[getUserInfo] done')

    def getSearchFields(self):
        '''
        return all fields on which a search could be made

        :return: dictionary of the search fields and their types
        :rtype:  dict
        '''
        log.debug("[getSearchFields]")

        sf = {}

        log.debug('[getSearchFields] done')
        return sf

    def getUserList(self, searchDict):
        '''
        retrieve a list of users

        :param searchDict: dictionary of the search criterias
        :type  searchDict: dict
        :return: list of user descriptions (as dict)
        '''
        log.debug("[getUserList] %s" % (str(searchDict)))

        ## we use a dict, where the return users are inserted to where key
        ## is userid to return only a distinct list of users
        try:
            uri = self.config['uri']
            timeout = self.config['timeout']

            username = self.config['authuser']
            password = self.config['password']
            certificate = self.config['certificate']

            credentials = {'user': username,
                           'password': password,
                           'certificate': certificate}

            # now prepare the query attributes
            s_uname = searchDict.get('username')
            s_uid = searchDict.get('userid')

            request_params = {'{USERID}': s_uid,
                              '{USERNAME}': s_uname,
                        '{PAGE}': '1',
                        '{PAGESIZE}': '10'
                        }

            request_path = self.config['userlist_request_path']
            request_mapping = self.config['userlist_request_mapping']
            result_path = self.config['userlist_result_path']
            result_mapping = self.config['userlist_result_mapping']

            result = IdResolver._do_request(uri, timeout, credentials,
                            request_path, request_mapping, request_params,
                            result_path, result_mapping)
            return result

        except Exception as exx:
            log.exception("%r" % exx)
            raise exx

        finally:
            log.debug('done')


if __name__ == "__main__":

    print "HTTPIdResolver - loading test"
    httpR = IdResolver()


##eof##########################################################################
