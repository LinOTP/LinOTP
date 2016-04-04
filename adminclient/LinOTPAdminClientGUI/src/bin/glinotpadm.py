#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
#
#    This file is part of LinOTP admin clients.
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
  GTK GUI to manage the LinOTP server
  and all Tokens. It communicates with the LinOTP server
  via the pylons controllers /admin and /system

  Dependencies: clientutil
"""

from linotpadminclientgui import __version__


import sys, os
import pygtk
pygtk.require("2.0")
import gtk
import re
import gobject
import ConfigParser
import locale
import gettext
import random
import platform
import pprint
import logging
import logging.handlers
import json
import types
from datetime import datetime
from configobj import ConfigObj, ParseError

from math import ceil
try:
    import psyco
    psyco.full()
except:
    pass

import glib

# our own modules
from linotpadminclientcli.clientutils import LinOTPClientError
import linotpadminclientcli.clientutils as clientutils

# yubikey
yubi_module = False
try:
    from  linotpadminclientcli.yubikey import *
    import yubico
    yubi_module = True
except:
    print "The yubico module python-yubico is not installed. You will not be able to enroll yubikeys"
    pass

# gui edition
import linotpadminclientgui.etokenng as lotpetng
import linotpadminclientgui.license as linotp_license

MARKCOLOR = '#fe8625'
TOKENPAGESIZE = 10000

#------------------------------------------------
# Do some setup stuff
#
# Determine LOCALE_DIR
system = platform.system()
locale.setlocale(locale.LC_ALL, '')
APP_NAME = "LinOTP2"
localedir_testfile = "de/LC_MESSAGES/LinOTP2.mo"
localeDirsLinux = ('.',
        'locale/',
        sys.prefix + '/share/locale/',
        '/usr/local/share/locale/'
        )
LOCALE_DIR = "/usr/local/share/locale"
if system == "Linux":
    for dir in localeDirsLinux:
        if os.path.isfile(dir + "/" + localedir_testfile):
            LOCALE_DIR = dir
            break

# Config File
CONFIGFILE = os.path.expanduser("~") + "/glinotpadm.cfg"
SECTIONHEADER = "glinotpadm"
GLADEFILE = "glinotpadm.glade"
# Determine Resourcedir
resourceDirsLinux = ('./',
        sys.prefix + '/share/linotpadm/',
        '/usr/local/share/linotpadm/')
resourceDirsWindows = (sys.prefix + '\\share\\linotpadm\\',
        'C:\\python26\\share\\linotpadm\\')

RESOURCEDIR = "FAIL"
if system == "Linux":
    for dir in resourceDirsLinux:
        if os.path.isfile(dir + GLADEFILE):
            RESOURCEDIR = dir
            break
    if RESOURCEDIR == "FAIL":
        print "Unable to find any glade file"
        sys.exit(1)
elif system == "Windows":
    LOCALE_DIR = sys.prefix + "\\share\\locale"
    for dir in resourceDirsWindows:
        if os.path.isfile(dir + GLADEFILE):
            RESOURCEDIR = dir
            break
    if RESOURCEDIR == "FAIL":
        print "Unable to find any glade file"
        sys.exit(1)
else:
    print "This program is only know to run on windows and Linux."
    print "You are running ", system
    sys.exit(1)

UIFILE = RESOURCEDIR + GLADEFILE

_ = gettext.gettext

class LinOTPGuiError(Exception):
    def __init__(self, id=10, description="LinOTPGuiError"):
        self.id = id
        self.description = description
    def getId(self):
        return self.id
    def getDescription(self):
        return self.description

    def __str__(self):
        ## here we lookup the error id - to translate
        return repr("ERR" + str(self.id) + ": " + self.description)


# Logging
LOG_FILENAME = os.path.expanduser("~") + '/glinotpadm.log'
LOG_COUNT = 5
LOG_SIZE = 5000000
LOG_LEVEL = logging.INFO

pp = pprint.PrettyPrinter(indent=4)





'''
Helper functions
'''

def getSerial():
    r = hex(random.randrange(4096, 65535))
    d = hex(int(datetime.now().strftime("%y%m%d%H%M")))
    return d[2:] + r[2:]

class LinOTPGui(object):
    serverConfigMapping = { 'DefaultSyncWindow' :   { 'int' : 'spinbuttonSyncWindow' },
                            'DefaultOtpLen' :       { 'int' : 'spinbuttonOTPLength' },
                            'DefaultCountWindow' :  { 'int' : 'spinbuttonCountWindow'},
                            'DefaultMaxFailCount' : { 'int' : 'spinbuttonMaxFailCount'},
                            'splitAtSign'   : { 'bool' : 'checkbuttonSplitAtSign' },
                            'SMSProvider' : { 'text' : 'entrySMSProvider' },
                            'SMSProviderConfig' : { 'text': 'entrySMSProviderConfig' },
                            'SMSProviderTimeout' : { 'text': 'entrySMSTimeout' },
                            'DefaultResetFailCount': { 'bool': 'checkbuttonSystemResetFailcounter' },
                            'FailCounterIncOnFalsePin' : { 'bool': 'checkbuttonSystemIncOnFalsePIN' },
                            'PrependPin' : {'bool': 'checkbuttonSystemPrependPIN' },
                            'AutoResync' : {'bool': 'checkbuttonSystemAutoResync' },
                            'AutoResyncTimeout' : {'text': 'entrySystemAutoResyncTimeout' },
                            'PassOnUserNotFound': {'bool': 'checkbuttonPassOnUserNotFound' },
                            'PassOnUserNoToken': {'bool': 'checkbuttonPassOnUserNoToken' },
                            'selfservice.realmbox' : {'bool' : 'checkbuttonSelfserviceRealmBox' },
                            'allowSamlAttributes' : {'bool' : 'checkbuttonSAMLattributes' },
                            'totp.timeStep' : { 'text' : 'entryTotpTimestep' , 'default' : '30'},
                            'totp.timeWindow' : { 'text' : 'entryTotpTimewindow', 'default' : '180'},
                            'totp.timeShift' : { 'text' : 'entryTotpTimeshift', 'default' : '0'},
                            'mayOverwriteClient' : { 'text' : 'entryOverwriteAuthenticationClient', 'default':''},
                            'OcraMaxChallenges' : { 'int' : 'spinbuttonOCRAmaxChallenge' , 'default':3 },
                            'OcraChallengeTimeout' : { 'text' : 'entryOCRATimeout', 'default':'1M' },
                            'OcraDefaultSuite' : { 'text' : 'entryOcraDefaultSuite' , 'default' : 'OCRA-1:HOTP-SHA256-8:QA08'},
                            'QrOcraDefaultSuite' : { 'text': 'entryQRDefaultSuite', 'default' : 'OCRA-1:HOTP-SHA256-6:C-QA64' }
                            }


    # Add the log message handler to the logger
    handler = logging.handlers.RotatingFileHandler(
                                                   LOG_FILENAME, maxBytes=LOG_SIZE, backupCount=LOG_COUNT)
    formatter = logging.Formatter("[%(asctime)s][%(name)s][%(levelname)s]:%(message)s")
    handler.setFormatter(formatter)
    log = logging.getLogger("LinOTPGui")
    log.setLevel(LOG_LEVEL)
    log.addHandler(handler)

    def busyCursor(self, state, w=None):
        return
        if None == w:
            w = self.gui_tokenview
        if type(w) == types.StringType:
            win = self.wtree.get_widget(w).get_window()
        else:
            win = w.get_window()

        c = gtk.gdk.Cursor(gtk.gdk.LEFT_PTR)
        if state:
            c = gtk.gdk.Cursor(gtk.gdk.WATCH)

        try:
            win.set_cursor(c)
        except Exception as e:
            print str(e)
    #    self.drainEventQueue()
    #
    #def drainEventQueue(block = gtk.FALSE):
    #    while gtk.events_pending():
    #        gtk.mainiteration(block)


    def __init__(self):
        """
        In this init we are going to display the main
        serverinfo window
        """
        self.CLIENTCONF = { 'ADMIN':"",
            'ADMINPW':"",
            'URL':"",
            'RETRYCOUNTER':'10',
            'DEFAULTTOKENNAME':"",
            'DISPLAYDURATION':'10',
            'UIFILE':"",
            'PORT':"",
            'PROTOCOL':"",
            'HOSTNAME':"",
            'RANDOMUSERPIN':'True',
            'RANDOMSOPIN':'True',
            'INITTOKEN' : 'True',
            'CLIENTCERT':"",
            'CLIENTKEY':"",
            'PROXY':None,
            'AUTHTYPE':"Digest"}
        self.status_pulse_on = False
        self.cr_serial = ""
        self.cfg = ConfigParser.SafeConfigParser()
        self.serverConfig = {}
        self.realmConfig = {}
        self.resolverConfig = {}
        self.policyDef = {}
        self.numToken = 0
        self.numUser = 0
        self.data_cache = {}
        self.readClientConfig()
        self.builder = gtk.Builder()
        # import the ui
        self.builder.add_from_file (UIFILE)

        self._setup_variables()

        self.builder.connect_signals(self)
        # set the translation domain
        gettext.bindtextdomain(APP_NAME, LOCALE_DIR)
        gettext.textdomain(APP_NAME)
        #gtk.glade.bindtextdomain(APP_NAME, LOCALE_DIR)
        #gtk.glade.textdomain(APP_NAME)
        #self.builder.set_translation_domain(APP_NAME)

        self.gui_tokenview.get_selection().set_mode(gtk.SELECTION_MULTIPLE)
        self.gui_userview.get_selection().set_mode(gtk.SELECTION_MULTIPLE)
        self.gui_tokenview.set_reorderable(True)
        self.gui_userview.set_reorderable(True)
        self.gui_poltreeview.set_reorderable(True)
        self.gui_tokenview.set_headers_clickable(True)
        self.gui_userview.set_headers_clickable(True)
        self.gui_poltreeview.set_headers_clickable(True)
        # We got one default REALM:
        self.obj_treestoreRealm.append(None, (0, "Default"))
        self.builder.get_object('buttonRenameRealm').hide()
        # initialization
        #self.obj_tokenlist.set_sort_column_id(0)
        #self.builder.get_object('notebook1').remove_page(-1)
        #if EDITION == "CE":
        #    self.builder.get_object('buttonEnrollToken').set_sensitive(False)
        # show and Filter token
        #      self.readtoken( )
        # progressbar
        self.progressbarImport = self.builder.get_object('progressbarImportToken')
        # do the filter

        self.obj_pollist_sort = gtk.TreeModelSort(self.obj_pollist)
        self.gui_poltreeview.set_model(self.obj_pollist_sort)

        self.tokenfilter = self.obj_tokenlist.filter_new()
        self.tokenfilter_sort = gtk.TreeModelSort(self.tokenfilter)
        self.gui_tokenview.set_model(self.tokenfilter_sort)

        self.builder.get_object('comboboxSerial').set_model(self.tokenfilter)
        self.eTokenfilter = ""
        self.tokenfilter.set_visible_func(self.tokenfilterfunc, self.eTokenfilter)
        # show users
        #self.userfilter = self.obj_userlist.filter_new()
        #self.userfilter_sort = gtk.TreeModelSort( self.userfilter)
        #self.gui_userview.set_model(self.userfilter_sort)
        #self.gui_comboboxUser.set_model(self.userfilter)
        #self.builder.get_object('comboboxUserEnroll').set_model(self.userfilter)
        #self.eUserfilter = ""
        #self.userfilter.set_visible_func( self.userfilterfunc, self.eUserfilter )

        self.obj_auditlist_sort = gtk.TreeModelSort(self.obj_auditlist)
        # audit filter combobox
        self.fill_audit_filter()


        self.userfilter = self.obj_userlist.filter_new()
        self.userfilter_sort = gtk.TreeModelSort(self.userfilter)
        self.gui_userview.set_model(self.userfilter_sort)
        self.gui_comboboxUser.set_model(self.userfilter)
        self.builder.get_object('comboboxUserEnroll').set_model(self.userfilter)
        self.builder.get_object('comboboxSerial').set_model(self.tokenfilter)
        self.eUserfilter = ""
        self.userfilter.set_visible_func(self.userfilterfunc, self.eUserfilter)
        # construct menuTokenPopup
        self.popupTokenMenu = self.builder.get_object('menuTokenActions')
        self.popupUserMenu = self.builder.get_object('menuUserActions')
        # translation
        for obj in self.builder.get_objects():
            if None != obj:
                if type(obj) in [ gtk.Label,
                                 gtk.Button,
                                 gtk.ToolButton,
                                 gtk.MenuItem,
                                 gtk.ImageMenuItem,
                                 gtk.RadioButton,
                                 gtk.CheckButton ]:
                    obj.set_label(_(obj.get_label()))

                elif type(obj) is gtk.TreeViewColumn:
                    obj.set_title(_(obj.get_title()))

                elif type(obj) in [ gtk.Dialog,
                                   gtk.FileChooserDialog,
                                   gtk.MessageDialog ]:
                    try:
                        obj.set_title(_(obj.get_title()))
                    except:
                        print "No translation for: ", obj
                    # avoid destroying the dialogs
                    obj.connect("delete-event", self.on_dialog_close)

                #else:
                #   print type(obj)
                #(tt, wdg, text, priv )=gtk.tooltips_data_get(obj)
                #gtk.tooltips.set_tip(obj, _(text))

        # Version
        self.builder.get_object('aboutdialog').set_version(__version__)
        self.builder.get_object('labelBuildVersion').set_text(__version__)
        # set images
        self.builder.get_object('image1').set_from_file(RESOURCEDIR + 'linotp_logo_200x68_72dpi.png')
        # Filefilter for Client Certs and key
        self.builder.get_object('filefilterCert').add_pattern('*.pem')
        self.builder.get_object('filefilterCert').add_pattern('*.crt')
        self.builder.get_object('filefilterCert').add_pattern('*.cer')
        self.builder.get_object('filefilterCert').add_pattern('*.key')
        # hide frames in Server Config
        self.builder.get_object('framePasswdIdResolver').hide()
        self.builder.get_object('frameLDAPIdResolver').hide()
        self.builder.get_object('frameSQLIdResolver').hide()
        # setup LinOTP server connection
        self.lotpclient = clientutils.linotpclient(self.CLIENTCONF['PROTOCOL'],
            self.CLIENTCONF['URL'],
            self.CLIENTCONF['ADMIN'],
            self.CLIENTCONF['ADMINPW'],
            self.CLIENTCONF['CLIENTCERT'],
            self.CLIENTCONF['CLIENTKEY'],
            self.CLIENTCONF['PROXY'],
            self.CLIENTCONF['AUTHTYPE'])
        self.log.info("Initialization done.")
        self.lotpclient.setLogging(logtoggle=True, param={
            'LOG_FILENAME':self.CLIENTCONF['LOGFILE'],
            'LOG_COUNT':self.CLIENTCONF['LOGCOUNT'],
            'LOG_SIZE':self.CLIENTCONF['LOGSIZE'],
            'LOG_LEVEL':(int(self.CLIENTCONF['LOGLEVEL']) + 1) * 10 })

        self.lic = linotp_license.licenseclient({ 'logging' : { 'LOG_FILENAME':self.CLIENTCONF['LOGFILE'],
                                        'LOG_COUNT':self.CLIENTCONF['LOGCOUNT'],
                                        'LOG_SIZE':self.CLIENTCONF['LOGSIZE'],
                                        'LOG_LEVEL':(int(self.CLIENTCONF['LOGLEVEL']) + 1) * 10 } });
        self.tokenpage = 0
        self.tokenpagesize = TOKENPAGESIZE
        self.tokenpagenum = 1
        self.initToolTips()
        self.refresh(self)
        splash.hide()

    def _setup_variables(self):
        '''
        do variables, do avoid time consuming lookup we do not
        want to do self.builder.get_object during runtime!!!
        '''
        self.gui_statusLabel2 = self.builder.get_object('statusLabel2')
        self.gui_statusLabel1 = self.builder.get_object('statusLabel1')
        self.gui_entryUser = self.builder.get_object('entryUser')
        self.gui_entryFilterUser = self.builder.get_object('entryFilterUser')
        # get objects
        self.gui_mainWindow = self.builder.get_object('mainWindow')
        self.gui_importdialog = self.builder.get_object('importTokenDialog')
        self.gui_aboutdialog = self.builder.get_object('aboutdialog')
        # Treeviews
        self.obj_tokenlist = self.builder.get_object('tokenstore')
        self.obj_userlist = self.builder.get_object('userstore')
        self.obj_auditlist = self.builder.get_object('liststoreAudit')
        self.obj_pollist = self.builder.get_object('policystore')
        self.gui_tokenview = self.builder.get_object('tokenTreeview')
        self.gui_userview = self.builder.get_object('userTreeview')
        self.gui_poltreeview = self.builder.get_object('treeviewpolicy')

        self.gui_entryFilter = self.builder.get_object('entryfilter')
        self.gui_entryTokenSearchPattern = self.builder.get_object('entryTokenSearchPattern')
        self.gui_entryTokenPage = self.builder.get_object('entryTokenPage')
        self.gui_labelTokenNum = self.builder.get_object('labelTokenNum')
        self.gui_entryUserSearchPattern = self.builder.get_object('entryUserSearchPattern')
        self.gui_comboboxUser = self.builder.get_object('comboboxUser')
        self.gui_statusLabelLicense = self.builder.get_object('statusLabelLicense')

        self.obj_treestoreRealm = self.builder.get_object('treestoreRealm')
        self.obj_treestoreTokeninfo = self.builder.get_object('treestoreTokeninfo')
        self.gui_progressbarEnroll = self.builder.get_object('progressbarEnroll')

    def initToolTips(self):
        for obj in self.builder.get_objects():
            if None != obj:
                # We just ignore objects, that do not provide tooltips
                try:
                    obj.set_tooltip_text(_(obj.get_tooltip_text()))
                except:
                    pass



    def readClientConfig(self):
        self.CLIENTCONF['PROTOCOL'] = 'http'
        self.CLIENTCONF['HOSTNAME'] = 'localhost'
        self.CLIENTCONF['PORT'] = '5001'
        self.CLIENTCONF['URL'] = self.CLIENTCONF['HOSTNAME'] + ":" + self.CLIENTCONF['PORT']
        self.CLIENTCONF['DEFAULTTOKENNAME'] = 'LinOTPToken'
        self.CLIENTCONF['RETRYCOUNTER'] = '10'
        self.CLIENTCONF['ADMIN'] = None
        self.CLIENTCONF['ADMINPW'] = None
        self.CLIENTCONF['CLIENTCERT'] = ""
        self.CLIENTCONF['CLIENTKEY'] = ""
        self.CLIENTCONF['PROXY'] = ""
        self.CLIENTCONF['RANDOMUSERPIN'] = 'True'
        self.CLIENTCONF['RANDOMSOPIN'] = 'True'
        self.CLIENTCONF['LOGFILE'] = os.path.expanduser("~") + '/glinotpadm.log'
        self.CLIENTCONF['LOGCOUNT'] = '5'
        self.CLIENTCONF['LOGSIZE'] = '5000000'
        self.CLIENTCONF['LOGLEVEL'] = '1'
        self.CLIENTCONF['CLEARUSERFILTER'] = 'True'
        try:
            if os.path.exists(CONFIGFILE):
                self.cfg.read(CONFIGFILE)
                for opt, value in self.CLIENTCONF.items():
                    if self.cfg.has_option(SECTIONHEADER, opt):
                        self.CLIENTCONF[opt] = self.cfg.get(SECTIONHEADER, opt)
                self.CLIENTCONF['URL'] = self.CLIENTCONF['HOSTNAME'] + ":" + self.CLIENTCONF['PORT']
        except IOError as e:
            self.popupError(e.getDescription())
            self.log.exception("readClientConfig: %s" % e.getDescription)

        # Re-Init the Logger
        self.log.setLevel((int(self.CLIENTCONF['LOGLEVEL']) + 1) * 10)
        self.log.removeHandler(self.handler)
        self.handler = logging.handlers.RotatingFileHandler(
            self.CLIENTCONF['LOGFILE'], maxBytes=self.CLIENTCONF['LOGSIZE'],
            backupCount=self.CLIENTCONF['LOGCOUNT'])
        self.handler.setFormatter(self.formatter)
        self.log.addHandler(self.handler)
        self.log.debug("readClientConfig success: %s" % pp.pformat(self.CLIENTCONF))

    def writeClientConfig(self, widget):
        try:
            if not self.cfg.has_section('glinotpadm'):
                self.cfg.add_section('glinotpadm')
            for opt, value in self.CLIENTCONF.items():
                # Do not save admin and adminpw
                if (opt != 'ADMINPW' and opt != 'ADMIN'):
                    self.cfg.set('glinotpadm', opt, str(self.CLIENTCONF[opt]))
            with open(CONFIGFILE, 'wb') as configfile:
                self.cfg.write(configfile)
        except IOError as e:
            self.popupError(e.getDescription())
            self.log.exception("writeClientConfig: %s" % e.getDescription)
        self.CLIENTCONF['URL'] = "{0}:{1}".format(self.CLIENTCONF['HOSTNAME'], self.CLIENTCONF['PORT'])
        self.log.debug("writeClientConfig success: %s" % pp.pformat(self.CLIENTCONF))
        self.lotpclient.setcredentials(self.CLIENTCONF['PROTOCOL'], self.CLIENTCONF['URL'],
                                        self.CLIENTCONF['ADMIN'], self.CLIENTCONF['ADMINPW'],
                                        self.CLIENTCONF['CLIENTCERT'], self.CLIENTCONF['CLIENTKEY'],
                                        self.CLIENTCONF['PROXY'], self.CLIENTCONF['AUTHTYPE'])
        self.lotpclient.setLogging(logtoggle=True, param={
            'LOG_FILENAME':self.CLIENTCONF['LOGFILE'],
            'LOG_COUNT':self.CLIENTCONF['LOGCOUNT'],
            'LOG_SIZE':self.CLIENTCONF['LOGSIZE'],
            'LOG_LEVEL':(int(self.CLIENTCONF['LOGLEVEL']) + 1) * 10 })

    def run(self):
        try:
            gtk.main()
        except KeyboardInterrupt:
            pass

    def read_resolver_config_old(self):
        for key, v in self.serverConfig.items():
            self.log.info("[readServerConfig]: Configkey= %s " % key)
            a = key.rsplit('.')
            if re.match("^sqlresolver", key):
                if len(a) == 2:
                    name = "_default_SQL_"
                elif len(a) == 3:
                    name = a[2]
                else:
                    break
                if not name in self.resolverConfig:
                    self.resolverConfig[name] = { "name": name, "type":"SQL" }
                self.resolverConfig[name][a[1]] = v
            elif re.match ("^ldapresolver", key):
                if len(a) == 2:
                    name = "_default_LDAP_"
                elif len(a) == 3:
                    name = a[2]
                else:
                    break
                if not name in self.resolverConfig:
                    self.resolverConfig[name] = { "name": name, "type":"LDAP" }
                self.resolverConfig[name][a[1]] = v
            elif re.match ("^passwdresolver", key):
                if len(a) == 2:
                    name = "_default_Passwd_"
                elif len(a) == 3:
                    name = a[2]
                else:
                    break
                if not name in self.resolverConfig:
                    self.resolverConfig[name] = { "name": name, "type":"Flatfile" }
                self.resolverConfig[name][a[1]] = v

        print self.resolverConfig

    def read_resolver_config(self):
        '''
          This function loads the resolver configuration via
          /system/getResolvers and /system/getResolver
        '''
        typeMap = { 'ldapresolver' : 'LDAP',
                    'sqlresolver' : 'SQL',
                    'passwdresolver' : 'Flatfile' }

        #self.busyCursor(True)
        try:
            rv = self.lotpclient.connect('/system/getResolvers', {})
            if rv['result']['status'] == True:
                resolvers = rv['result']['value']
                for res in resolvers.keys():
                    self.resolverConfig[res] = { 'name' : resolvers[res].get('resolvername'),
                                                'type' : typeMap.get(resolvers[res].get('type')) }

            # Now we got the names of all resolvers and now we load them
            for res_name in self.resolverConfig.keys():
                rv = self.lotpclient.connect('/system/getResolver', { 'resolver' : res_name })
                if rv['result']['status'] == True:
                    res_data = rv['result']['value']['data']
                    for k, v in res_data.items():
                        self.resolverConfig[res_name][k] = v

            #print pp.pformat( self.resolverConfig )

        except LinOTPClientError as e:
            if e.getId() in [ 1005, 1006 ]:
                self.loginLinOTPServer(self)
            else:
                self.popupError(_("Error reading resolver configuration from server: %s") % e.getDescription())
            self.log.exception("read_resolver_config: %s" % e.getDescription)

        #self.busyCursor(False)


    def readServerConfig(self):
        '''
        this function reads the server configuration and the realms settings from the
        server by using the client functions
            readserverconfig()
            getrealms()
        The following configuration dictionaries are set:
            self.serverConfig:   the complete server config
            self.resolverConfig: the configuration of the resolvers
            self.realmConfig:    the configuration of the realms
        '''
        #self.busyCursor(True)
        try:
            rv = self.lotpclient.readserverconfig({})
            if rv['result']['status'] == True:
                self.serverConfig = rv['result']['value']
        except LinOTPClientError as e:
            if e.getId() in [1005, 1006]:
                self.loginLinOTPServer(self)
            else:
                self.popupError(_("Error reading system configuration from server: %s") % e.getDescription())
            self.log.exception("readServerConfig: %s" % e.getDescription)

        try:
            rv = self.lotpclient.getrealms({})
            if rv['result']['status'] == True:
                self.realmConfig = rv['result']['value']
        except LinOTPClientError as e:
            if e.getId() in [1005, 1006]:
                self.loginLinOTPServer(self)
            else:
                self.popupError(_("Error reading realm configuration from server: %s") % e.getDescription())
            self.log.exception("readServerConfig: %s" % e.getDescription)


        # Read the resolver configuration
        self.resolverConfig = {}
        self.read_resolver_config()
        self.fill_treestoreRealm()

        self.log.debug("[readServerConfig] success Config  : %s" % pp.pformat(self.serverConfig))
        self.log.debug("[readServerConfig] success Realm   : %s" % pp.pformat(self.realmConfig))
        self.log.debug("[readServerConfig] success Resolver: %s" % pp.pformat(self.resolverConfig))

        #self.busyCursor(False)

    def writeResolverConfig(self):
        #self.busyCursor(True)
        try:
            for name, res in self.resolverConfig.items():
                param = {}
                param['name'] = name
                for key, value in res.items():
                    if "type" == key:
                        if "SQL" == value:
                            param['type'] = "sqlresolver"
                        elif "LDAP" == value:
                            param['type'] = "ldapresolver"
                        elif "Flatfile" == value:
                            param['type'] = "passwdresolver"
                    else:
                        param[key] = value
                self.lotpclient.connect('/system/setResolver', param)

        except LinOTPClientError as e:
            if e.getId() in [1005, 1006]:
                self.loginLinOTPServer(self)
            else:
                self.popupError(_("Error writing resolver configuration to server: %s") % e.getDescription())
            self.log.exception("writeResolverConfig %s" % e.getDescription())
        self.log.debug("writeResolverConfig success: %s" % pp.pformat(self.serverConfig))

        #self.busyCursor(False)

    def writeServerConfig(self):
        #self.busyCursor(True)
        try:
            if self.serverConfig.has_key('Config'):
                del self.serverConfig['Config']
            self.lotpclient.writeserverconfig(self.serverConfig)
        except LinOTPClientError as e:
            if e.getId() in [1005, 1006]:
                self.loginLinOTPServer(self)
            else:
                self.popupError(_("Error writing configuration to server: %s") % e.getDescription())
            self.log.exception("writeServerConfig %s" % e.getDescription())
        self.log.debug("writeServerConfig success: %s" % pp.pformat(self.serverConfig))

        self.writeResolverConfig()
        self.writeServerConfigRealm()
        #self.busyCursor(False)


    def readtoken(self):
        #self.busyCursor(True)
        self.setStatusLine(_("Fetching tokenlist from server"))
        task = self._readtoken()
        gobject.idle_add(task.next)

    def _readtoken(self):
        # Filter
        tokenfilter = self.gui_entryTokenSearchPattern.get_text()

        try:
            self.log.debug(">>>> start to read token from server")
            self.obj_tokenlist.clear()
            numToken = 0
            #rv = self.lotpclient.listtoken(  { 'pagesize':self.tokenpagesize, 'page':self.tokenpage},)
            rv = self.lotpclient.listtoken({ 'filter' : tokenfilter })
            self.log.debug(">>>>> done reading tokens from server.")
            # Check if the server already supports paging
            if rv['result']['value'].has_key('resultset'):
                pageresult = rv['result']['value']['resultset']
                self.tokenpagenum = pageresult['pages']
                self.tokenpage = pageresult['page']
                self.gui_entryTokenPage.set_text("%d" % pageresult['page'])
                self.gui_labelTokenNum.set_text("%d" % pageresult['pages'])

            data = rv['result']['value']['data']
            # Hide the model from the list to speed up things
            self.gui_tokenview.freeze_child_notify()
            self.gui_tokenview.set_model(None)
            tl = self.obj_tokenlist
            tlins = tl.insert
            self.log.info(">>>>> populating tokenlist")
            for token in data:
                # split string into list and get last element
                resolver = ""
                if len(token['LinOtp.IdResClass']):
                    resolver = token['LinOtp.IdResClass'].split(".")[-1]
                tlins(0, (
                    token["LinOtp.TokenSerialnumber"],
                    token["User.username"],
                    token["LinOtp.Isactive"],
                    token["LinOtp.FailCount"],
                    token["LinOtp.MaxFail"],
                    token["LinOtp.CountWindow"],
                    token["LinOtp.TokenDesc"],
                    token["LinOtp.TokenType"],
                    resolver,
                    ','.join(token["LinOtp.RealmNames"]),
                    ))
                numToken += 1
                if (numToken % 50) == 0:
                    self.setStatusLine(_("populating token list (%s)") % numToken)
                    yield True

            self.obj_tokenlist = tl
            # switch the model back
            self.gui_tokenview.set_model(self.obj_tokenlist)
            self.gui_tokenview.thaw_child_notify()
            self.tokenfilter = self.obj_tokenlist.filter_new()
            # do the sorting
            self.tokenfilter_sort = gtk.TreeModelSort(self.tokenfilter)
            self.gui_tokenview.set_model(self.tokenfilter_sort)
            self.eTokenfilter = ""
            self.tokenfilter.set_visible_func(self.tokenfilterfunc, self.eTokenfilter)
            self.on_entryfilter_changed(self)

            self.log.info(">>>>> tokenlist populated")
            if rv['result']['value'].has_key('resultset'):
                self.setStatusLine(_("%s tokens found") % pageresult['tokens'])
            else:
                self.setStatusLine(_("LinOTP Server does not support paging!"))
            self.numToken = pageresult['tokens']
            self.log.debug("tokens filled.")
            self.license_get()
            #self.busyCursor(False)
        except LinOTPClientError as e:
            # check if we cannot connect due to authentication
            if e.getId() in [1005, 1006]:
                self.loginLinOTPServer(self)
            else:
                self.popupError(e.getDescription() +
                    "\n\n" + _("Please setup the LinOTP Server in the Admin Client configuration correctly"))


    def readuser(self):
        '''
        This method reads the userlist from the server
        '''
        #self.busyCursor(True)

        self.setStatusLine(_("Fetching userlist from server"), 2)
        task = self._readuser()
        gobject.idle_add(task.next)

    def _readuser(self):
        # Filter
        # add filterfield for username and realm!
        #        https://localhost/admin/userlist?realm=realmAD&username=*38*
        userfilter = self.gui_entryUserSearchPattern.get_text()
        if "" == userfilter:
            userfilter = "*"
        aiter = self.builder.get_object('comboboxSearchRealm').get_active_iter()
        if aiter:
            realm = self.builder.get_object('realmstore2').get(aiter, 0)[0]
        else:
            realm = "*"
        param = { "username": userfilter, "realm": realm }
        # param = { "username":"*" } # this only lists the default realm!
        try:
            self.obj_userlist.clear()
            numUser = 0
            self.log.debug(">>>> start to read users from server")
            rv = self.lotpclient.userlist(param)
            self.log.debug(">>>> done reading users from server")
            data = rv['result']['value']
            self.log.debug(">>>> populating user list")
            # Hide the model from the list to speed up things
            self.gui_userview.freeze_child_notify()
            self.gui_userview.set_model(None)
            ul = self.obj_userlist
            sulins = ul.insert
            #map( self.sulins, data )
            for user in data:
                uidresolver = user.get("useridresolver", user.get("resolver"))
                uidres = uidresolver.split('.')
                lenu = len(uidres)
                if lenu == 4:
                    uidresolver = "%s" % uidres[3]
                elif lenu == 3:
                    uidresolver = "<<%s>>" % uidres[1]
                sulins(0, (
                    user.get("username"),
                    user.get("givenname"),
                    user.get("surname"),
                    user.get("email"),
                    user.get("phone"),
                    user.get("mobile"),
                    uidresolver
                    ))
                numUser = numUser + 1
                if (numUser % 100) == 0:
                    self.setStatusLine(_("populating user list (%s)") % numUser, 2)
                    yield True

            self.obj_userlist = ul
            # switch the model back
            self.gui_userview.set_model(self.obj_userlist)
            self.gui_userview.thaw_child_notify()
            self.userfilter = self.obj_userlist.filter_new()
            # do the sorting
            self.setStatusLine(_("sorting user list of %s users") % numUser, 2)
            self.do_pulse()

            self.userfilter_sort = gtk.TreeModelSort(self.userfilter)
            self.gui_userview.set_model(self.userfilter_sort)
            self.gui_comboboxUser.set_model(self.userfilter)
            self.builder.get_object('comboboxUserEnroll').set_model(self.userfilter)

            self.setStatusLine(_("setting filter for user list of %s users") % numUser, 2)
            self.do_pulse()
            self.eUserfilter = ""
            self.userfilter.set_visible_func(self.userfilterfunc, self.eUserfilter)

            self.on_entryFilterUser_changed(self)

            self.do_pulse()
            self.log.debug(">>>> userlist populated")
            self.setStatusLine(_("%s users found") % numUser, 2)
            #self.busyCursor(False)

            self.numUser = numUser
            self.log.debug("users filled.")

        except LinOTPClientError as e:
            # check if we cannot connect due to authentication
            if e.getId() in [1005, 1006]:
                self.loginLinOTPServer(self)
            else:
                self.popupError(e.getDescription() +
                    "\n\n" + _("Please setup the LinOTP Server in the Admin Client configuration correctly"))


    def readaudit(self, widget=None):
        param = {'sortname' : 'number',
                 'sortorder' : 'desc' }
        page = 1
        rp = 100

        try:
            page = int(self.builder.get_object('entryAuditPage').get_text())
            if page <= 0:
                page = 1
                self.builder.get_object('entryAuditPage').set_text(str(page))
        except:
            pass
        try:
            rp = int(self.builder.get_object('entryAuditLinesPerPage').get_text())
            if rp <= 0:
                rp = 100
                self.builder.get_object('entryAuditLinesPerPage').set_text(str(rp))
        except:
            pass

        param['page'] = page
        param['rp'] = rp

        # get additional sql filter
        column = ""
        aiter = self.builder.get_object('comboboxAuditFilter').get_active_iter()
        if aiter:
            sql_column = self.builder.get_object('liststoreAuditFilter').get(aiter, 0)[0]
            if "" != sql_column:
                value = self.builder.get_object('entryAuditFilter').get_text()
                param[sql_column] = u'' + value

        try:

            self.obj_auditlist.clear()
            self.log.debug(">>>> start to read audit from server")

            # first we get the pagenum
            param['page'] = 1
            rv = self.lotpclient.auditsearch(param)
            self.builder.get_object('labelAuditTotalLines').set_text(str(rv['total']))
            pagenum = int(ceil (float(rv['total']) / float(rp)))
            self.builder.get_object('labelAuditPageNum').set_text("/ %d" % pagenum)

            if page > pagenum:
                page = pagenum
                self.builder.get_object('entryAuditPage').set_text(str(page))

            # now we get the real page
            param['page'] = page
            rv = self.lotpclient.auditsearch(param)
            data = rv['rows']
            for line in data:
                self.obj_auditlist.append(line['cell'])

            # switch the model back
            self.obj_auditlist_sort = gtk.TreeModelSort(self.obj_auditlist)
            self.builder.get_object('treeviewAudit').set_model(self.obj_auditlist_sort)

        except LinOTPClientError as e:
            if e.getId() in [1005, 1006]:
                self.loginLinOTPServer(self)
            else:
                self.popupError(e.getDescription() +
                    "\n\n" + _("Error reading audit information"))

    def fill_audit_filter(self):
        '''
        fills the audit filter with values
        '''
        for name in  [ ('', ''), ('user', _('user')),
                      ('realm', _('realm')) , ('serial', _('serial')),
                      ('administrator', _('admin')),
                      ('success', _('success')), ('action', _('action')),
                      ('action_detail', _('action detail')), ('signature', _('signature')),
                      ('tokentype', _('token type')), ('info', _('info')),
                      ('timestamp', _('date')), ('log_level', _('log level')),
                      ('linotp_server', _('LinOTP server')),
                      ('client', _('Client'))]:
            self.builder.get_object('liststoreAuditFilter').append(name)

    def importtoken(self, protocol, url, param):
        try:
            if not param['file']:
                raise LinOTPGuiError(1002, _("LinOTPGui::importtoken - Please specify a filename to import the token from."))
            f = open (param['file'])
            tokenfile = f.readlines()
            f.close
            tokenserial = ""
            tokenseed = ""
            tokens = 0
            token_count = 0
            for line in tokenfile:
                mt = re.search('<Token serial=\"(.*)\">', line)
                if mt:
                    token_count = token_count + 1
            for line in tokenfile:
                #<Token serial="F800574">
                #<Seed>F71E5AC721B7353735F52494E61B1A62538A0238</Seed>
                mt = re.search('<Token serial=\"(.*)\">', line)
                if mt:
                    if tokenseed:
                        raise LinOTPGuiError(1004, _("LinOTPGui::importtoken - got a seed %s without a serial") % tokenseed)
                    else:
                        tokenserial = mt.group(1)
                        tokens = tokens + 1
                        # update progressbar
                        self.displayprogress(self, tokens, token_count, tokenserial)
                        while gtk.events_pending():
                            gtk.main_iteration()

                else:
                    ms = re.search('<Seed>(.*)</Seed>', line)
                    if ms:
                        tokenseed = ms.group(1)
                        if tokenserial:
                            init_param = { 'serial':tokenserial,
                                'otpkey':tokenseed,
                                'description':"Safeword/etPASS",
                                'user':'', 'pin':''}
                            if 'hashlib' in param:
                                init_param['hashlib'] = param['hashlib']
                            self.lotpclient.inittoken(init_param)
                            # CKO: remove the data
                            del tokenseed
                            tokenseed = ""
                        else:
                            self.popupError(_("LinOTPGui::importtoken - got a seed %s without a serial") % tokenseed)

        except IOError as e:
            self.popupError(_("LinOTPGui::importtoken - I/O error : %s") % e)
            self.log.exception("importtoken: %s" % e.getDescription)
        except LinOTPClientError as e:
            if e.getId() in [1005, 1006]:
                self.loginLinOTPServer(self)
            else:
                self.popupError(e.getDescription())
        except LinOTPGuiError as e:
            self.popupError(e.getDescription())
        self.refresh(self)

    def quit(self, widget):
        gtk.main_quit()

    def get_selected_serials(self):
        serials = []
        selected_token = self.gui_tokenview.get_selection()
        tokenstore, selected_rows = selected_token.get_selected_rows()
        if (len(selected_rows) == 0):
            self.popupError(_("No Token selected"))
        else:
            for row in selected_rows:
                item = tokenstore.get_iter_first()
                i = 0
                while (item != None):
                    self.setStatusLine(_("gathering selected tokens"))
                    if i == row[0]:
                        serial = tokenstore.get_value(item, 0)
                        serials.append(serial)
                        self.setStatusLine(_("gathering token: %s") % serial)
                        self.do_pulse()
                        break
                    i = i + 1
                    item = tokenstore.iter_next(item)
        return serials

    def get_selected_users(self):
        users = []
        selected_users = self.gui_userview.get_selection()
        userstore, selected_rows = selected_users.get_selected_rows()
        if (len(selected_rows) == 0):
            self.popupError(_("No user selected"))
        else:
            for row in selected_rows:
                self.setStatusLine(_("gathering selected users"))
                item = userstore.get_iter_first()
                i = 0
                while (item != None):
                    self.do_pulse()
                    if i == row[0]:
                        loginname = userstore.get_value(item, 0)
                        surname = userstore.get_value(item, 1)
                        givenname = userstore.get_value(item, 2)
                        email = userstore.get_value(item, 3)
                        phone = userstore.get_value(item, 4)
                        mobile = userstore.get_value(item, 5)
                        resolver = userstore.get_value(item, 6)
                        users.append({ 'loginname':loginname,
                            'resolver':resolver,
                            'surname':surname,
                            'givenname':givenname,
                            'email':email,
                            'phone':phone,
                            'mobile':mobile,
                            })
                        self.setStatusLine(_("gathering user: %s") % loginname)
                        self.do_pulse()
                        break
                    i = i + 1
                    item = userstore.iter_next(item)
        return users

    def displayprogress(self, widget, token, count, serial, text="Tokens imported"):
        fraction = float(token) / float(count)
        self.progressbarImport.set_fraction(fraction)
        self.progressbarImport.set_text(_("(%(s)s) %(t)d of %(c)d %(te)s") % { 's':serial, 't':token, 'c':count, 'te' : text })
        # ...to speed things up
        if (token % 10 == 0):
            self.readtoken()

    def tokenfilterfunc(self, model, iter, filter):
        # We do caseINsensitive matching
        #self.log.debug(" filter: X ")
        searchoption = re.IGNORECASE
        filter = self.eTokenfilter
        if filter == "": return True
        #self.log.debug("[tokenfilterfunc] >>>>> eTokenfilter set to: %s" % self.eTokenfilter)
        #self.log.debug("[tokenfilterfunc] >>>>> filter set to: %s" % filter)
        self.log.debug(" filter: 0 ")
        (serial, user, realm, descr, type, active) = model.get(iter, 0, 1, 8, 6, 7, 2)
        self.log.debug("[tokenfilterfunc] >>>>>  %s" % filter)
        #self.log.debug(" filter: 1 ")
        res = re.match
        self.log.debug(" filter: 2 ")
        #serial = model.get_value(iter, 0)
        if not serial is None:
            self.log.debug(" filter: 3 ")
            if res(filter, serial, searchoption) != None:
                self.log.debug(" filter: 4 ")
                return True
        # check in user
        if not user is None:
            if res(filter, user, searchoption) != None:
                return True
        # check in realm
        if not realm is None:
            if res(filter, realm, searchoption) != None:
                return True
        # also take a look in the description
        if not descr is None:
            if res(filter, descr, searchoption) != None:
                return True
        #type
        if not type is None:
            if res(filter, type, searchoption) != None:
                return True
        #active = str(model.get_value(iter, 2))
        #if not active is None:
        #    if res(filter, active, searchoption) != None:
        #        result = True
        return False

    def userfilterfunc(self, model, iter, filter):
        searchoption = re.IGNORECASE
        if self.eUserfilter == "": return True
        filter = self.eUserfilter
        result = False
        for i in range(0, 5):
            if model.get_value(iter, i):
                value = model.get_value(iter, i)
                if re.search(filter, value, searchoption) != None:
                    result = True
        return result

    def userfilterfunc2(self, model, iter, filter):
        #return True
        self.log.debug("[userfilterfunc] filter: %s " % self.eUserfilter)
        searchoption = re.IGNORECASE
        filter = self.eUserfilter
        if filter == "": return True
        (username, resolver, surname, givenname, email, phone, mobile) = model.get(iter, 0, 1, 2, 3, 4, 5, 6)
        res = re.match
        self.log.debug("[userfilterfunc] username: %s / filter: %s" % (username, filter))
        if not username is None:
            self.log.debug("[userfilterfunc] username exists")
            if res(filter, username, searchoption) != None:
                self.log.debug("[userfilterfunc] ...and matches")
                return True

        self.log.debug("[userfilterfunc] returning false")
        return False

    def popupError(self, message):
        self.builder.get_object('messagedialogError').format_secondary_text(message)
        self.builder.get_object('messagedialogError').set_title(_("Error"))
        self.builder.get_object('messagedialogError').show()

    def popupInfo(self, message):
        self.builder.get_object('messagedialogInfo').format_secondary_text(message)
        self.builder.get_object('messagedialogError').set_title(_("Info"))
        self.builder.get_object('messagedialogInfo').show()

    def feedback(self, rt, success, fail):
        if rt['result']['value'] == True:
            self.popupInfo(success)
        else:
            self.popupError(fail)

    def feedback_set(self, rt, check, success, fail):
        # {u'jsonrpc': u'2.0', u'result': {u'status': True, u'value': {u'set pin': 1}}, u'id': 1}
        if rt['result']['value'][check] == 1:
            self.popupInfo(success)
        else:
            self.popupError(fail)

#####CALLBACKS

    def on_buttonErrorOk_clicked(self, widget):
        self.builder.get_object('messagedialogError').hide()

    def on_buttonInfoOK_clicked(self, widget):
        self.builder.get_object('messagedialogInfo').hide()


##### File operations

    def select_logfile(self, widget):
        dialog = gtk.FileChooserDialog(_("Select logfile"),
            None,
            gtk.FILE_CHOOSER_ACTION_OPEN,
            (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
            gtk.STOCK_OPEN, gtk.RESPONSE_OK))
        dialog.set_default_response(gtk.RESPONSE_OK)
        filter = gtk.FileFilter()
        filter.set_name(_("Log files"))
        filter.add_pattern("*.log")
        dialog.add_filter(filter)

        filter = gtk.FileFilter()
        filter.set_name(_("All files"))
        filter.add_pattern("*")
        dialog.add_filter(filter)

        response = dialog.run()
        if response == gtk.RESPONSE_OK:
            self.builder.get_object('entryLogFile').set_text(dialog.get_filename())
        dialog.destroy()

    def on_useYubikeyUnlock(self, widget):
        '''
        This function is called for enrolling the Yubikey,
        when the checkbox whether using an unlock key is clicked
        '''
        use_unlock_key = self.builder.get_object('checkbuttonYubikeyUnlock').get_active()
        self.builder.get_object('entryYubikeyUnlock').set_sensitive(use_unlock_key)


    def on_newYubikeyUnlock(self, widget):
          '''
          This function is triggered, if the user chooses to set a new unlock key
          '''
          new_unlock_key = self.builder.get_object('rbYAcc_new').get_active()
          print self.builder.get_object('rbYAcc_new').get_active()
          print self.builder.get_object('rbYAcc_same').get_active()
          print self.builder.get_object('rbYAcc_no').get_active()
          self.builder.get_object('entryYubikeyUnlockNew').set_sensitive(new_unlock_key)


    def on_buttonClientCert_clicked(self, widget):
        dialog = gtk.FileChooserDialog(_("Select client certificate"),
            None,
            gtk.FILE_CHOOSER_ACTION_OPEN,
            (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
            gtk.STOCK_OPEN, gtk.RESPONSE_OK))
        dialog.set_default_response(gtk.RESPONSE_OK)
        filter = gtk.FileFilter()
        filter.set_name(_("certificate files"))
        filter.add_pattern("*.der")
        filter.add_pattern("*.pem")
        filter.add_pattern("*.crt")
        filter.add_pattern("*.cer")
        dialog.add_filter(filter)

        filter = gtk.FileFilter()
        filter.set_name(_("All files"))
        filter.add_pattern("*")
        dialog.add_filter(filter)

        response = dialog.run()
        if response == gtk.RESPONSE_OK:
            self.builder.get_object('entryClientCert').set_text(dialog.get_filename())
        dialog.destroy()

    def on_buttonClientKey_clicked(self, widget):
        dialog = gtk.FileChooserDialog(_("Select client certificate"),
            None,
            gtk.FILE_CHOOSER_ACTION_OPEN,
            (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
            gtk.STOCK_OPEN, gtk.RESPONSE_OK))
        dialog.set_default_response(gtk.RESPONSE_OK)
        filter = gtk.FileFilter()
        filter.set_name(_("private key files"))
        filter.add_pattern("*.key")
        filter.add_pattern("*.pem")
        filter.add_pattern("*.der")
        dialog.add_filter(filter)

        filter = gtk.FileFilter()
        filter.set_name(_("All files"))
        filter.add_pattern("*")
        dialog.add_filter(filter)

        response = dialog.run()
        if response == gtk.RESPONSE_OK:
            self.builder.get_object('entryClientKey').set_text(dialog.get_filename())
        dialog.destroy()

    def on_buttonImport_clicked(self, widget):
        self.builder.get_object('dialogImport').show()

    def on_import_cancel(self, widget):
        self.builder.get_object('dialogImport').hide()

    def on_import_ok(self, widget):
        self.builder.get_object('dialogImport').hide()
        hashlib = self.builder.get_object('comboboxHashlib').get_active_text()
        if "" == hashlib or None == hashlib:
            hashlib = "sha1"
        filename = self.builder.get_object("entryImportFile").get_text()
        self.importtoken(self.CLIENTCONF['PROTOCOL'], self.CLIENTCONF['URL'], { 'file': filename,
                                                                                    'hashlib': hashlib })

    def choose_import_file(self, hashlib="sha1"):
        dialog = gtk.FileChooserDialog(_("Select Token definition file"),
            None,
            gtk.FILE_CHOOSER_ACTION_OPEN,
            (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
            gtk.STOCK_OPEN, gtk.RESPONSE_OK))
        dialog.set_default_response(gtk.RESPONSE_OK)
        filter = gtk.FileFilter()
        filter.set_name(_("All files"))
        filter.add_pattern("*")
        dialog.add_filter(filter)

        filter = gtk.FileFilter()
        filter.set_name(_("Token file"))
        filter.add_pattern("*.dat")
        filter.add_pattern("*.xml")
        dialog.add_filter(filter)

        response = dialog.run()
        filename = None
        if response == gtk.RESPONSE_OK:
            filename = dialog.get_filename()
        dialog.destroy()
        if filename:
            self.builder.get_object("entryImportFile").set_text(filename)

##### Token details

    def fill_tokeninfo(self, serial):
          rv = self.lotpclient.connect("/admin/show", {'serial':serial})
          type = "hmac"
          if rv['result']['status']:
                self.obj_treestoreTokeninfo.clear()
                data = rv['result']['value']['data'][0]
                # TODO fill the trreeview with the hash
                for k in data:
                    if "LinOtp.RealmNames" == k:
                        new_iter = self.obj_treestoreTokeninfo.append(None, (k, ""))
                        for realm in data[k]:
                            self.obj_treestoreTokeninfo.append(new_iter, ("", realm))
                    elif "LinOtp.TokenInfo" == k:
                        new_iter = self.obj_treestoreTokeninfo.append(None, (k, ""))
                        try:
                            tinfo = json.loads(data[k])
                        except:
                            tinfo = {}
                        for info in tinfo:
                            self.obj_treestoreTokeninfo.append(new_iter, (info, tinfo[info]))
                    else:
                        if "LinOtp.TokenType" == k:
                            type = data[k].lower()
                        new_iter = self.obj_treestoreTokeninfo.append(None, (k, data[k]))
          return type



    def on_token_details(self, widget):
        serials = self.get_selected_serials()
        if len(serials) != 1:
            self.popupError(_("You need to select exactly one token to display it's details."))
        else:
            self.builder.get_object('dialogTokeninfo').show()
            self.builder.get_object('dialogTokeninfo').set_title(_("Tokeninfo for token %s") % serials[0])
            self.builder.get_object('labelTokeninfoSerial').set_text(serials[0])
            type = self.fill_tokeninfo(serials[0])
            # TOTP
            totp_visible = ("totp" == type.lower())
            self.builder.get_object('toolbuttonTimeWindow').set_visible(totp_visible)
            self.builder.get_object('toolbuttonTimeStep').set_visible(totp_visible)

    def on_token_info_close(self, widget):
        self.builder.get_object('dialogTokeninfo').hide()

    def dialogSetHashlib(self, widget):
        serial = widget.get_text()
        self._dialogSetTokenInfo(serial, "hashlib")

    def dialogSetTimeWindow(self, widget):
        serial = widget.get_text()
        self._dialogSetTokenInfo(serial, "timeWindow")

    def dialogSetTimeStep(self, widget):
        serial = widget.get_text()
        self._dialogSetTokenInfo(serial, "timeStep")

    def dialogSetOTPLen(self, widget):
        serial = widget.get_text()
        self._dialogSetTokenInfo(serial, "OtpLen")

    def dialogSetCounterWindow(self, widget):
        serial = widget.get_text()
        self._dialogSetTokenInfo(serial, "CounterWindow")

    def dialogSetSyncWindow(self, widget):
        serial = widget.get_text()
        self._dialogSetTokenInfo(serial, "SyncWindow")

    def dialogSetMaxFailCount(self, widget):
        serial = widget.get_text()
        self._dialogSetTokenInfo(serial, "MaxFailCount")

    def _token_info_type(self, combo=False):
        self.builder.get_object('labelSetTokeninfoCombo').set_visible(combo)
        self.builder.get_object('labelSetTokeninfoEntry').set_visible(not combo)
        self.builder.get_object('entrySetTokeninfo').set_visible(not combo)
        self.builder.get_object('comboboxSetTokeninfo').set_visible(combo)

    def _dialogSetTokenInfo(self, serial, key):
      self.setTokeninfoKey = key
      self.builder.get_object('dialogSetTokeninfo').show()
      _cb = self.builder.get_object('comboboxSetTokeninfo')
      _model = self.builder.get_object('liststoreTokeninfoCombo')
      _model.clear()
      if key in ['hashlib', 'timeStep', 'OtpLen']:
          self._token_info_type(combo=True)
      else:
          self._token_info_type(combo=False)

      info = ""
      if "hashlib" == key:
          info = _("eTokenPASS are available with HMAC-SHA-1 or HMAC-SHA-256 algorithm.\n\
The newer eToken Pass (starting with version 6.20) are using SHA-256.\n\
You may take a look into the XML file for the version number!\n\
Please choose the right Algorithm.\n")
          _model.append()
          _model.append(["sha1"])
          _model.append(["sha256"])
      elif "timeStep" == key:
          info = _("Timebased OATH tokens either generate a new OTP value every 30 or every 60 seconds.")
          _model.append(["30"])
          _model.append(["60"])
      elif "OtpLen" == key:
          _model.append(["6"])
          _model.append(["8"])
      elif "timeWindow" == key:
          info = _("For timebased OATH tokens this is the amount of seconds\n\
LinOTP will try to find the matching OTP value before and after the currentime.")
      elif "CountWindow" == key:
          info = _("For eventbased OATH tokens this is the window of the allowed blank presses.")
      elif "MaxFailCount" == key:
          info = _("After that many failed authentication tries the token will be locked")
      elif "SyncWindow" == key:
          info = _("When doing a manual or an auto resync this is the number of OTP values that will be calculated in the future.")


      self.builder.get_object('labelTokeninfoHelp').set_text(info)
      self.builder.get_object('labelSetTokeninfoEntry').set_text(_("Setting %s for token %s") % (key, serial))
      self.builder.get_object('labelSetTokeninfoCombo').set_text(_("Select %s for token %s") % (key, serial))


    def on_setTokeninfo_cancel(self, widget):
        self.builder.get_object('dialogSetTokeninfo').hide()

    def on_setTokeninfo_ok(self, widget):
          self.builder.get_object('dialogSetTokeninfo').hide()
          serial = self.builder.get_object('labelTokeninfoSerial').get_text()
          key = self.setTokeninfoKey

          if key in ["hashlib", "timeStep", "OtpLen"]:
              value = self.builder.get_object('comboboxSetTokeninfo').get_active_text()
          elif key in ["timeWindow", "CountWindow", "SyncWindow", "MaxFailCount"]:
              value = self.builder.get_object('entrySetTokeninfo').get_text()
          else:
              self.popupError(_("Unhandled Tokeninfo key: %s!") % key)
              return

          ret = self.lotpclient.connect('/admin/set', { 'serial': serial, key : value })
          if (ret['result']['status']):
              self.popupInfo(_("Successfully set the %s") % key)
              self.fill_tokeninfo(serial)
          else:
              self.popupError(_("Failed to set the %s!") % key)



##### User Popup functions

    def preset_comboboxuser(self, combobox, presetuser):
        '''
        This function presets the combobox (either comboboxUser or ComboboxUserEnroll)
        with a given user.
        user is a dictionary and has to have the entries
            loginname
            resolver
        '''
        iter = self.userfilter.get_iter_first()
        while iter != None:
            user = self.userfilter.get(iter, 0)[0]
            resConf = self.userfilter.get(iter, 6)[0]
            if user == presetuser['loginname'] and resConf == presetuser['resolver']:
                self.builder.get_object(combobox).set_active_iter(iter)
                break
            iter = self.userfilter.iter_next(iter)

    def on_popupuser_assign(self, widget):
        users = self.get_selected_users()
        if (len(users) != 1):
            self.popupError(_("You are trying to assign a Token to a very user. You may only select one user!"))
        self.builder.get_object('comboboxSerial').show()
        self.builder.get_object('entryTokenSerials').set_sensitive(True)
        self.builder.get_object('entryTokenSerials').set_text('')
        self.builder.get_object('dialogAssign').show()
        self.builder.get_object('entryUser').set_text(users[0]['loginname'])

        self.preset_comboboxuser('comboboxUser', users[0])


    def on_entryTokenSerials_changed(self, widget):
        if (self.builder.get_object('entryTokenSerials').get_property('sensitive') == True):
            self.eTokenfilter = self.builder.get_object('entryTokenSerials').get_text()
            self.gui_entryFilter.set_text(self.eTokenfilter)
            self.tokenfilter.refilter()

    def on_comboboxSerial_changed(self, widget):
        aiter = self.builder.get_object('comboboxSerial').get_active_iter()
        if aiter:
            self.builder.get_object('entryTokenSerials').set_text(self.tokenfilter.get(aiter, 0)[0])

    def on_popupuser_enroll(self, widget):
        users = self.get_selected_users()
        if (len(users) != 1):
            self.popupError(_("You are trying to enroll a Token to a very user. You may only select one user!"))
        self.builder.get_object('checkbuttonInitToken').set_active(self.CLIENTCONF['INITTOKEN'] == "True")
        self.builder.get_object('dialogEnroll').show()
        self.builder.get_object('frameTokenMOTP').hide()
        self.builder.get_object('comboboxTokenType').set_active(0)
        self.builder.get_object('buttonEnrollOK').set_sensitive(True)
        self.gui_progressbarEnroll.set_fraction(0)
        self.gui_progressbarEnroll.set_text(_('Please insert token'))
        self.builder.get_object('entryEnrollUser').set_text(users[0]['loginname'])

        self.preset_comboboxuser('comboboxUserEnroll', users[0])

    def on_popupuser_enable(self, widget):
        users = self.get_selected_users()
        try:
            for u in users:
                self.lotpclient.enabletoken({'user':u['loginname'], 'resConf':u['resolver']})
        except LinOTPClientError as e:
            self.popupError(e.getDescription())
            self.log.exception("user enable: %s" % e.getDescription)
        self.readtoken()

    def on_popupuser_disable(self, widget):
        users = self.get_selected_users()
        try:
            for u in users:
                self.setStatusLine(_("disabling token for user %s") % u)
                self.lotpclient.disabletoken({'user':u['loginname'], 'resConf':u['resolver']})
                self.do_pulse()
        except LinOTPClientError as e:
            self.popupError(e.getDescription())
            self.log.exception("user disable: %s" % e.getDescription)
        self.readtoken()

##### Token functions

    def do_pulse(self):
        while gtk.events_pending():
                    gtk.main_iteration()

    def on_disabletoken_clicked(self, widget):
        serials = self.get_selected_serials()
        try:
            i = 0
            for s in serials:
                self.setStatusLine(_("disabling token %s") % s)
                self.lotpclient.disabletoken({'serial':s})
                # update progressbar
                i = i + 1
                self.displayprogress(self, i , len(serials) , s, _("disabled"))
                self.do_pulse()

        except LinOTPClientError as e:
            self.popupError(e.getDescription())
            self.log.exception("token disable: %s" % e.getDescription)
        self.readtoken()
        self.clear_progressbar()

    def on_enabletoken_clicked(self, widget):
        serials = self.get_selected_serials()
        try:
            i = 0
            for s in serials:
                self.setStatusLine(_("enabling token %s") % s)
                self.lotpclient.enabletoken({'serial':s})
                # update progressbar
                i = i + 1
                self.displayprogress(self, i , len(serials) , s, _("enabled"))
                self.do_pulse()
        except LinOTPClientError as e:
            self.popupError(e.getDescription())
            self.log.exception("token enable: %s" % e.getDescription)
        self.readtoken()
        self.clear_progressbar()

    def on_removetoken_clicked(self, widget):
        serials = self.get_selected_serials()
        try:
            i = 0
            for s in serials:
                self.setStatusLine(_("removing token %s") % s)
                self.lotpclient.removetoken({'serial':s})
                # update progressbar
                i = i + 1
                self.displayprogress(self, i , len(serials) , s, _("removed"))
                self.do_pulse()
        except LinOTPClientError as e:
            self.popupError(e.getDescription())
            self.log.exception("token remove: %s" % e.getDescription)
        self.readtoken()
        self.clear_progressbar()

    def on_menuitemAbout_activate(self, widget):
        self.gui_aboutdialog.show()

    def on_aboutdialog_close(self, widget):
        self.gui_aboutdialog.hide()

    def on_aboutdialog_response(self, widget, resp):
        self.gui_aboutdialog.hide()

  # copy Token PIN
    def on_copytokenpin_open(self, widget):
        self.builder.get_object('dialogCopyTokenPin').show()

    def on_copytokenpin_close(self, widget):
        self.builder.get_object('dialogCopyTokenPin').hide()

    def on_copytokenpin(self, widget):
        param = {}
        param['from'] = self.builder.get_object('entryFromToken').get_text()
        param['to'] = self.builder.get_object('entryToToken').get_text()

        try:
            r = self.lotpclient.copytokenpin(param)
            result = r.get('result', None)
            if None != result:
                if True == result.get('status'):
                    if True == result.get('value'):
                        self.popupInfo("Successfully copied token PIN.")
                    else:
                        self.popupError("Error copying token PIN.")
                else:
                    self.popupError(result.get('error', {}).get('message', "Error"))

        except LinOTPClientError as e:
            self.popupError(e.getDescription())
            self.log.exception("get serial by OTP: %s" % e.getDescription)

    # audit buttons
    def on_button_audit_next_clicked(self, widget):
        # "/ %d" % pagenum
        max_page = 1000
        try:
            pagenum_s = self.builder.get_object('labelAuditPageNum').get_text()
            m = re.search("\/ (\d*)", pagenum_s)
            max_page = int(m.group(1))
        except:
            pass
        page = int(self.builder.get_object('entryAuditPage').get_text() or 1)
        if page <= 0:
            page = 1
        page += 1
        if page > max_page:
            page = max_page
        self.builder.get_object('entryAuditPage').set_text(str(page))
        self.readaudit()

    def on_button_audit_prev_clicked(self, widget):
        page = int(self.builder.get_object('entryAuditPage').get_text() or 1)
        page -= 1
        if page <= 0:
            page = 1

        self.builder.get_object('entryAuditPage').set_text(str(page))
        self.readaudit()

    def on_button_import_policy_clicked(self, widget):
        '''
        When this button is clicked we open a dialog to import policies
        '''
        filename = ""
        dialog = gtk.FileChooserDialog(_("Load a policy file"),
                                       None,
                                       gtk.FILE_CHOOSER_ACTION_OPEN,
                                       (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                                        gtk.STOCK_OPEN, gtk.RESPONSE_OK))
        dialog.set_default_response(gtk.RESPONSE_OK)
        filter = gtk.FileFilter()
        filter.set_name(_("policy config"))
        filter.add_pattern("*.cfg")
        dialog.add_filter(filter)
        filter = gtk.FileFilter()
        filter.set_name(_("All files"))
        filter.add_pattern("*")
        dialog.add_filter(filter)

        response = dialog.run()

        if response == gtk.RESPONSE_OK:
            filename = dialog.get_filename()
            try:
                policy_file = ConfigObj(filename)
                for policy_name in policy_file.keys():
                    print policy_name
                    policy = policy_file[policy_name]
                    rv = self.lotpclient.connect('/system/setPolicy', {
                        'name' : policy_name,
                        'user' : policy.get("name"),
                        'action' : policy.get("action"),
                        'scope' : policy.get("scope"),
                        'realm' : policy.get("realm"),
                        'client' : policy.get("client"),
                        'time' : policy.get("time")
                    })
            except ParseError as e:
                self.popupError(_("Could not parse policy file: %s") % str(e))
        dialog.destroy()
        self.listPolicy()


    def on_button_export_policy_clicked(self, widget):
        '''
        When this button is pressed the policies are exported.
        '''
        data = self.lotpclient.get_policy()
        result = data.get('result')
        if result:
            if result.get('status') == True:
                # We got a result and can safe it to a file.
                policy = result.get('value', {})
                # replace None by ""
                for pol, value in policy.items():
                    for k in value.keys():
                        value[k] = value[k] or ""
                filename = ""
                dialog = gtk.FileChooserDialog(_("Save the policy file"),
                                               None,
                                               gtk.FILE_CHOOSER_ACTION_SAVE,
                                               (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                                                gtk.STOCK_SAVE, gtk.RESPONSE_OK))
                dialog.set_default_response(gtk.RESPONSE_OK)
                filter = gtk.FileFilter()
                filter.set_name(_("policy config"))
                filter.add_pattern("*.cfg")
                dialog.add_filter(filter)
                filter = gtk.FileFilter()
                filter.set_name(_("All files"))
                filter.add_pattern("*")
                dialog.add_filter(filter)
                again = True
                while again:
                    again = False
                    response = dialog.run()
                    if response == gtk.RESPONSE_OK:
                        filename = dialog.get_filename()
                        do_it = True
                        if os.path.exists(filename):
                            # file exist, ask if overwrite
                            do_it = self.question_dialog(_("The file %s already exist. Overwrite?") % filename)
                        if do_it:
                            try:
                                policy_file = ConfigObj()
                                policy_file.filename = filename
                                for name in policy.keys():
                                    policy_file[name] = policy[name]
                                    policy_file.write()
                                self.popupInfo(_("Successfully saved policy file."))
                            except IOError as e:
                                self.log.error("[on_button_export_policy_clicked]: Error writing file: %s" % e.getDescription)
                                self.popupError(e.getDescription() + "\n\n" + _("Error writing policy file."))
                        else:
                            again = True

                dialog.destroy()


    # get serial by OTP
    def on_getserial_open(self, widget):
        self.builder.get_object('dialogGetSerialByOtp').show()
        self.builder.get_object('entryToolsGetSerialOTP').set_text("")
        self.builder.get_object('entryToolsGetSerialType').set_text("")


    def on_getserial_close(self, widget):
        self.builder.get_object('dialogGetSerialByOtp').hide()

    def on_getserial(self, widget):
        param = {}
        otp = self.builder.get_object('entryToolsGetSerialOTP').get_text()
        param['otp'] = otp
        type = self.builder.get_object('entryToolsGetSerialType').get_text()
        if "" != type:
            param['type'] = type

        # get selected realm
        aiter = self.builder.get_object('comboboxToolsGetSerialRealm').get_active_iter()
        if aiter:
            realm = self.builder.get_object('realmstore_getserial').get(aiter, 0)[0]
            if "" != realm:
                param['realm'] = realm
        # get selected assign
        aiter = self.builder.get_object('comboboxToolsGetSerialAssigned').get_active_iter()
        if aiter:
            assigned = self.builder.get_object('liststore_assigned').get(aiter, 0)[0]
            if -1 != assigned:
                param['assigned'] = assigned

        try:
            r = self.lotpclient.getserialbyotp(param)
            '''
              {u'version': u'LinOTP 2.4', u'jsonrpc': u'2.0', u'result': {u'status': True, u'value': {u'serial': u'vc0091234582', u'success': True}}, u'id': 1}
              '''
            result = r.get('result', None)
            if None != result:
                if True == result.get('status'):
                    value = result.get('value')
                    if True == value.get('success'):
                        if "" != value.get('serial', ""):
                            text = _("Found the token serial: %s") % value.get('serial')
                            if value.get('user_login') != "":
                                text = text + _("\nThe token belongs to %s (%s)") % (value.get('user_login'), value.get('user_resolver'))
                            self.popupInfo(text)
                        else:
                            self.popupInfo(_("Could not find a matching token serial for the given OTP value."))
        except LinOTPClientError as e:
            self.popupError(e.getDescription())
            self.log.exception("get serial by OTP: %s" % e.getDescription)

    def on_buttonAssign_clicked(self, widget):
        # get the serials in an array
        serials = self.get_selected_serials()
        self.builder.get_object('entryTokenSerials').set_text(','.join(serials))
        self.builder.get_object('entryTokenSerials').set_sensitive(False)
        self.builder.get_object('comboboxSerial').hide()
        self.builder.get_object('dialogAssign').show()

    def on_buttonUnassign_clicked(self, widget):
        self.builder.get_object('dialogAssign').hide()
        serials = self.get_selected_serials()
        try:
            i = 0;
            for s in serials:
                self.setStatusLine(_("unassigning token %s") % s)
                self.lotpclient.unassigntoken({'serial':s})
                # update progressbar
                i = i + 1
                self.displayprogress(self, i , len(serials) , s, _("unassigned"))
                self.do_pulse()
        except LinOTPClientError as e:
            self.popupError(e.getDescription())
            self.log.exception("token unassign: %s" % e.getDescription)
        self.readtoken()
        self.clear_progressbar()

    def on_buttonAssignCancel_clicked(self, widget):
        self.builder.get_object('dialogAssign').hide()


    def get_current_combobox_user(self, combobox):
        '''
        returns a dictionary with loginname and the resConf name of a selected user in
        either the combobox
            comboboxUser (for assigning) or
            comboboxUserEnroll (for enrolling)
        '''
        aiter = self.builder.get_object(combobox).get_active_iter()
        user = { 'loginname':'',
                'resolver':'',
                'givenname':'',
                'surname':'',
                'mobile':'',
                'phone':'',
                'email':'' }
        if aiter:
            if self.userfilter.get(aiter, 0)[0]:
                user['loginname'] = self.userfilter.get(aiter, 0)[0]
            if self.userfilter.get(aiter, 1)[0]:
                user['givenname'] = self.userfilter.get(aiter, 1)[0]
            if self.userfilter.get(aiter, 2)[0]:
                user['surname'] = self.userfilter.get(aiter, 2)[0]
            if self.userfilter.get(aiter, 3)[0]:
                user['email'] = self.userfilter.get(aiter, 3)[0]
            if self.userfilter.get(aiter, 4)[0]:
                user['phone'] = self.userfilter.get(aiter, 4)[0]
            if self.userfilter.get(aiter, 5)[0]:
                user['mobile'] = self.userfilter.get(aiter, 5)[0]
            if self.userfilter.get(aiter, 6)[0]:
                user['resolver'] = self.userfilter.get(aiter, 6)[0]
        return user

    def on_buttonAssignOK_clicked(self, widget):
        # Token serials must not contain a ','
        serials = self.builder.get_object('entryTokenSerials').get_text().rsplit(',')
        user = self.get_current_combobox_user('comboboxUser')
        if '' == user['loginname']:
            self.popupError(_("No user selected"))
        else:
            try:
                i = 0
                for s in serials:
                    self.setStatusLine(_("assigning token %s") % s)
                    self.lotpclient.assigntoken({'serial':s, 'user' : user['loginname'], 'resConf':user['resolver']})
                    # update progressbar
                    i = i + 1
                    self.displayprogress(self, i , len(serials) , s, _("assigned"))
                    self.do_pulse()
            except LinOTPClientError as e:
                self.popupError(e.getDescription())
                self.log.exception("token assign: %s" % e.getDescription)
            self.builder.get_object('dialogAssign').hide()
            self.readtoken()
            self.clear_progressbar()


    def reset_failcounter(self, widget):
        serials = self.get_selected_serials()
        for s in serials:
            try:
                self.lotpclient.resetfailcounter({'serial':s})
            except LinOTPClientError as e:
                self.popupError(e.getDescription())
                self.log.exception("reset failcounter: %s" % e.getDescription)
        self.readtoken()

##### Enroll Tokens

    def displayenrollprogress(self, step, all, status):
        fraction = float(step) / float(all)
        self.gui_progressbarEnroll.set_fraction(fraction)
        self.gui_progressbarEnroll.set_text(status)

    def on_entryEnrollPIN_changed(self, widget):
        if (self.builder.get_object('entryEnrollUserPIN1').get_text() !=
            self.builder.get_object('entryEnrollUserPIN2').get_text()):
            self.builder.get_object('entryEnrollUserPIN1').modify_base(
                gtk.STATE_NORMAL, gtk.gdk.color_parse("red"))
            self.builder.get_object('entryEnrollUserPIN2').modify_base(
                gtk.STATE_NORMAL, gtk.gdk.color_parse("red"))
        else:
            self.builder.get_object('entryEnrollUserPIN1').modify_base(
                gtk.STATE_NORMAL, gtk.gdk.color_parse("green"))
            self.builder.get_object('entryEnrollUserPIN2').modify_base(
                gtk.STATE_NORMAL, gtk.gdk.color_parse("green"))
        if (self.builder.get_object('entryEnrollSOPIN1').get_text() !=
            self.builder.get_object('entryEnrollSOPIN2').get_text()):
            self.builder.get_object('entryEnrollSOPIN1').modify_base(
                gtk.STATE_NORMAL, gtk.gdk.color_parse("red"))
            self.builder.get_object('entryEnrollSOPIN2').modify_base(
                gtk.STATE_NORMAL, gtk.gdk.color_parse("red"))
        else:
            self.builder.get_object('entryEnrollSOPIN1').modify_base(
                gtk.STATE_NORMAL, gtk.gdk.color_parse("green"))
            self.builder.get_object('entryEnrollSOPIN2').modify_base(
                gtk.STATE_NORMAL, gtk.gdk.color_parse("green"))

        self.builder.get_object('buttonEnrollOK').set_sensitive(
            (self.builder.get_object('entryEnrollUserPIN1').get_text() ==
            self.builder.get_object('entryEnrollUserPIN2').get_text()) and
            (self.builder.get_object('entryEnrollSOPIN1').get_text() ==
            self.builder.get_object('entryEnrollSOPIN2').get_text())
            )



    def question_dialog(self, question, buttons=gtk.BUTTONS_OK_CANCEL):
        message = gtk.MessageDialog(None, gtk.DIALOG_MODAL,
                    gtk.MESSAGE_QUESTION,
                    buttons,
                    question)
        resp = message.run()
        message.destroy()
        if resp == gtk.RESPONSE_OK:
                return True
        return False


    def enroll_task(self, username="", resConf="", userpin="", sopin=""):
        i = 1
        if username != "":
            tokenname = username
        else:
            tokenname = self.CLIENTCONF['DEFAULTTOKENNAME']
        try:
            doIt = True
            if self.builder.get_object('checkbuttonInitToken').get_active():
                if not self.question_dialog(_("The eTokenNG OTP will be initialized. All data on the Token will be lost.")):
                    doIt = False
            if doIt:
                while i <= 8:
                    if i == 1:
                        self.displayenrollprogress(1, 7, _("starting to enroll eToken-NG OTP"))
                        enroller = lotpetng.etng({'label':tokenname,
                            'RetryCounter': self.CLIENTCONF['RETRYCOUNTER'],
                            'displayDuration':self.CLIENTCONF['DISPLAYDURATION'],
                            'randomUserPIN': self.CLIENTCONF['RANDOMUSERPIN'],
                            'randomSOPIN': self.CLIENTCONF['RANDOMSOPIN'],
                            'userpin': userpin,
                            'sopin': sopin,
                            'logging' : { 'LOG_FILENAME':self.CLIENTCONF['LOGFILE'],
                                        'LOG_COUNT':self.CLIENTCONF['LOGCOUNT'],
                                        'LOG_SIZE':self.CLIENTCONF['LOGSIZE'],
                                        'LOG_LEVEL':(int(self.CLIENTCONF['LOGLEVEL']) + 1) * 10 } ,
                            'debug':False },
                            )
                        yield True
                    elif i == 2:
                        self.displayenrollprogress(2, 7, _("initialize pkcs11 interface"))
                        enroller.initpkcs11()
                        yield True
                    elif i == 3:
                        if self.builder.get_object('checkbuttonInitToken').get_active():
                            self.displayenrollprogress(3, 7, _("initialize token"))
                            enroller.inittoken()
                        yield True
                    elif i == 4:
                        self.displayenrollprogress(4, 7, _("login to token"))
                        enroller.logintoken()
                        yield True
                    elif i == 5:
                        self.displayenrollprogress(5, 7, _("delete old OTP application"))
                        enroller.deleteOTP()
                        yield True
                    elif i == 6:
                        self.displayenrollprogress(6, 7, _("create new OTP application"))
                        enroller.createOTP()
                        yield True
                    elif i == 7:
                        self.displayenrollprogress(7, 7, _("finalizing token"))
                        tdata = enroller.finalize()
                        yield True
                    elif i == 8:
                        param = { 'otpkey':tdata['hmac'],
                            'serial':tdata['serial'],
                            'description':'eTokenNG-OTP',
                            'userpin':tdata['userpin'],
                            'sopin':tdata['sopin']}
                        if username != "":
                            param['user'] = username
                            param['resConf'] = resConf
                        self.lotpclient.inittoken(param)
                        self.lotpclient.setscpin(param)
                        # CKO: remove the data
                        del param
                        del tdata
                        self.readtoken()
                        self.builder.get_object('dialogEnroll').hide()
                        self.enroll_clear_pins()
                    i = i + 1
                yield False
            else:
                self.builder.get_object('buttonEnrollOK').set_sensitive(True)

        except (LinOTPGuiError, lotpetng.etngError, LinOTPClientError) as e:
            self.popupError(e.getDescription())
            self.log.exception("enroll etoken NG: %s" % e.getDescription)

    def on_buttonEnrollOK_clicked(self, widget):
        '''
        The button OK on the enrollment dialog was clicked.
        '''
        user = self.get_current_combobox_user('comboboxUserEnroll')
        print user
        username = user['loginname']
        resConf = user['resolver']
        print resConf
        ttype = self.builder.get_object('comboboxTokenType').get_active()
        # Type = eToken NG OTP
        if (ttype == 0):
            self.builder.get_object('buttonEnrollOK').set_sensitive(False)
            task = self.enroll_task(username, resConf,
                userpin=self.builder.get_object('entryEnrollUserPIN1').get_text(),
                sopin=self.builder.get_object('entryEnrollSOPIN1').get_text())
            gobject.idle_add(task.next)
        # Type = mOTP
        elif (ttype == 1):
            key = self.builder.get_object('entryMOTPKey').get_text()
            pin = self.builder.get_object('entryMOTPPin').get_text()
            serial = self.builder.get_object('entryMOTPSerial').get_text()
            if (key != '' and pin != ''):
                if  (not re.match("[0-9a-fA-F]{32}$", key)) and (not re.match("[0-9a-fA-F]{24}$", key)) and (not re.match("[0-9a-fA-F]{16}$", key)):
                    self.popupInfo(_('The mOTP Key needs to be 16, 24 or 32 characters!'))
                elif (not re.match("\d\d\d\d$", pin)):
                    self.popupInfo(_('The mOTP Pin needs to be 4 digits!'))
                else:
                    if (serial == ''):
                        # invent some serial number
                        serial = "motp%04d" % self.numToken
                        i = 0
                        serialchars = "0123456789ABCDEFX"
                        while i < 6:
                            serial += serialchars[ int(random.uniform(0, len(serialchars)))]
                            i = i + 1
                    # initialize the motp
                    try:
                        self.lotpclient.inittoken({ 'serial':serial,
                            'type':'MOTP',
                            'otpkey':key,
                            'description':"mOTP",
                            'user':username,
                            'resConf':resConf,
                            'otppin':pin})
                    except LinOTPClientError as e:
                        self.popupError(e.getDescription())
                        self.log.exception("enroll mOTP: %s" % e.getDescription)
                        del key
                    # CKO: remove the data
                    del key
                    self.popupInfo(_('mOTP Token initialized successfully.'))
                    self.builder.get_object('dialogEnroll').hide()
                    self.builder.get_object('entryMOTPKey').set_text('')
                    self.builder.get_object('entryMOTPPin').set_text('')
                    self.builder.get_object('entryMOTPSerial').set_text('')
                    self.enroll_clear_pins()
                    self.readtoken()
            else:
                self.popupInfo(_('You need to enter a PIN and a KEY.'))
        # Type = OATH / HMAC OTP
        # Type = TOTP timebased
        elif (ttype == 2) or (ttype == 6):
            key = self.builder.get_object('entryHMACSeed').get_text()
            if (key != ''):
                if (not re.match("^[0-9a-fA-F]*$", key)):
                    self.popupInfo(_('The HMAC Key must only contain hex characters!'))
                elif (not len(key) in [ 32, 40, 48, 64 ]):
                    self.popupInfo(_('The HMAC Key needs to be 32, 40, 48 or 64 characters long, which is 128, 160, 192 or 256 bit!'))
                else:
                    # invent some serial number
                    serial = "hotp%04d" % self.numToken
                    if (ttype == 6):
                        serial = "totp%04d" % self.numToken
                    i = 0
                    serialchars = "0123456789ABCDEFX"
                    while i < 4:
                        serial += serialchars[ int(random.uniform(0, len(serialchars)))]
                        i = i + 1
                    # initialize the oath
                    try:
                        type = "HMAC"
                        if (ttype == 6):
                            type = "totp"
                        self.lotpclient.inittoken({ 'serial':serial,
                            'type':type,
                            'otpkey':key,
                            'description':"oath token",
                            'user':username,
                            'resConf':resConf })
                        self.popupInfo(_('OATH Token initialized successfully.'))
                        self.readtoken()
                    except LinOTPClientError as e:
                        self.popupError(e.getDescription())
                        self.log.exception("enroll OATH / HMAC-OTP: %s" % e.getDescription)
                    # CKO: remove the data
                    del key
                    self.builder.get_object('dialogEnroll').hide()
                    self.builder.get_object('entryHMACSeed').set_text('')
                    self.enroll_clear_pins()
            else:
                    self.popupInfo(_('You need to enter a Seed.'))
        # SPass Token
        elif (ttype == 3):
            serial = "LSSP%04d" % self.numToken
            i = 0
            serialchars = "0123456789ABCDEFX"
            while i < 4:
                serial += serialchars[ int(random.uniform(0, len(serialchars)))]
                i = i + 1
            try:
                self.lotpclient.inittoken({ 'serial':serial,
                    'type':'spass',
                    'otpkey':'1234',
                    'description':'Always Authenticate',
                    'user':username,
                    'resConf':resConf })
            except LinOTPClientError as e:
                self.popupError(e.getDescription())
                self.log.exception("enroll SPass: %s" % e.getDescription)
            self.popupInfo(_('SPass Token enrolled successfully.'))
            self.builder.get_object('dialogEnroll').hide()
            self.readtoken()
        # SMS OTP
        elif (ttype == 4):
            phone = self.builder.get_object('entrySMSPhone').get_text()
            serial = "LSSM%04d" % self.numToken
            i = 0
            serialchars = "0123456789ABCDEFX"
            while i < 4:
                serial += serialchars[ int(random.uniform(0, len(serialchars)))]
                i = i + 1
            try:
                self.lotpclient.inittoken({ 'serial':serial,
                    'type':'sms',
                    'phone' : phone,
                    'description':phone + ' admin enrolled',
                    'user':username,
                    'resConf':resConf })
            except LinOTPClientError as e:
                self.popupError(e.getDescription())
                self.log.exception("enroll SMS token: %s" % e.getDescription)
            self.popupInfo(_('SMS Token enrolled successfully.'))
            self.builder.get_object('dialogEnroll').hide()
            self.readtoken()
        # YubiKey
        elif (ttype == 5):
            if not yubi_module:
                self.popupError(_("The python-yubico module is not installed. You can not enroll yubikeys"))
            else:
                slot = 2
                if self.builder.get_object('rbYSlot').get_active():
                    slot = 1

                self.popupInfo(_("Please insert the YubiKey"))
                access_key = binascii.unhexlify('000000000000')
                unlock_key = binascii.unhexlify('000000000000')
                if self.builder.get_object('checkbuttonYubikeyUnlock').get_active():
                    # get unlock and access key
                    try:
                        unlock_key = binascii.unhexlify(self.builder.get_object('entryYubikeyUnlock').get_text())
                    except TypeError:
                        self.popupError(_("You need to enter the unlock key with 6 bytes in HEX format like: 10FF2B1212EE"))
                        return

                if self.builder.get_object('rbYAcc_new').get_active():
                    try:
                        access_key = binascii.unhexlify(self.builder.get_object('entryYubikeyUnlockNew').get_text())
                    except TypeError:
                        self.popupError(_("You need to enter enter the new unlock key with 6 bytes in HEX format like: 10FF2B1212EE"))
                        return
                elif self.builder.get_object('rbYAcc_same').get_active():
                    access_key = unlock_key

                try:
                    append_cr = self.builder.get_object('checkbuttonYEnter').get_active()
                    (hmac, serial) = enrollYubikey(digits=6, APPEND_CR=append_cr,
                                                    unlock_key=unlock_key,
                                                    access_key=access_key,
                                                    slot=slot)
                    #print hmac
                    r1 = self.lotpclient.inittoken({ 'serial':'UBOM%s_%s' % (serial, slot),
                        'type':'hmac',
                        'otpkey' : hmac,
                        'description':'YubiKey pyGUI enrolled.',
                        'user':username,
                        'resConf':resConf })
                    if r1['result']['value']:
                        self.popupInfo(_('YubiKey enrolled successfully.'))
                    else:
                        self.popupError(_('Failed to enroll YubiKey.'))
                except yubico.yubico_exception.YubicoError as e:
                    self.popupError(str(e))
                except YubiError as e:
                    self.popupError(e.value)
                except LinOTPClientError as e:
                    self.popupError(e.getDescription())

                self.builder.get_object('dialogEnroll').hide()
                self.readtoken()
        # Remote Token
        elif (ttype == 7):
            remoteServer = self.builder.get_object('entryRemoteServer').get_text()
            remoteSerial = self.builder.get_object('entryRemoteSerial').get_text()
            remoteUser = self.builder.get_object('entryRemoteUser').get_text()
            remoteRealm = self.builder.get_object('entryRemoteRealm').get_text()
            remoteResConf = self.builder.get_object('entryRemoteResolver').get_text()
            remoteLocalCheckpin = self.builder.get_object('comboboxRemoteLocalCheckpin').get_active()
            serial = "LSRE" + getSerial()
            try:
                r1 = self.lotpclient.inittoken({ 'serial':serial,
                                'type':'remote',
                                'description': remoteServer,
                                'remote.server':remoteServer,
                                'remote.serial':remoteSerial,
                                'remote.user':remoteUser,
                                'remote.realm':remoteRealm,
                                'remote.resConf':remoteResConf,
                                'remote.local_checkpin':remoteLocalCheckpin})
                if r1['result']['value']:
                    self.popupInfo(_("Remote Token with serial %s enrolled successfully.") % serial)
                else:
                    self.popupError(_("Failed to enroll Token with serial %s.") % serial)
            except LinOTPClientError as e:
                self.popupError(e.getDescription())
            self.builder.get_object('dialogEnroll').hide()
            self.readtoken()
        # RADIUS Token
        elif (ttype == 8):
            radiusServer = self.builder.get_object('entryRadiusServer').get_text()
            radiusSecret = self.builder.get_object('entryRadiusSecret').get_text()
            radiusUser = self.builder.get_object('entryRadiusUser').get_text()

            radiusLocalCheckpin = self.builder.get_object('comboboxRadiusLocalCheckpin').get_active()
            serial = "LSRA" + getSerial()
            try:
                r1 = self.lotpclient.inittoken({ 'serial':serial,
                                'type':'radius',
                                'description': 'radius:%s' % radiusServer,
                                'radius.server':radiusServer,
                                'radius.secret':radiusSecret,
                                'radius.user':radiusUser,
                                'radius.local_checkpin':radiusLocalCheckpin})
                if r1['result']['value']:
                    self.popupInfo(_("RADIUS Token with serial %s enrolled successfully.") % serial)
                else:
                    self.popupError(_("Failed to enroll Token with serial %s.") % serial)
            except LinOTPClientError as e:
                self.popupError(e.getDescription())
            self.builder.get_object('dialogEnroll').hide()
            self.readtoken()

        if self.CLIENTCONF['CLEARUSERFILTER'] == 'True':
            self.builder.get_object('entryFilterUser').set_text("")
            self.builder.get_object('entryEnrollUser').set_text("")

    def enroll_clear_pins(self):
        self.builder.get_object('entryEnrollUserPIN1').set_text("")
        self.builder.get_object('entryEnrollUserPIN2').set_text("")
        self.builder.get_object('entryEnrollSOPIN1').set_text("")
        self.builder.get_object('entryEnrollSOPIN2').set_text("")
        self.builder.get_object('entryEnrollUserPIN1').modify_base(
                gtk.STATE_NORMAL, gtk.gdk.color_parse("white"))
        self.builder.get_object('entryEnrollUserPIN2').modify_base(
                gtk.STATE_NORMAL, gtk.gdk.color_parse("white"))
        self.builder.get_object('entryEnrollSOPIN1').modify_base(
                gtk.STATE_NORMAL, gtk.gdk.color_parse("white"))
        self.builder.get_object('entryEnrollSOPIN2').modify_base(
                gtk.STATE_NORMAL, gtk.gdk.color_parse("white"))



    def on_buttonEnrollCancel_clicked(self, widget):
        self.builder.get_object('dialogEnroll').hide()
        self.builder.get_object('comboboxUserEnroll').set_active(-1)
        self.enroll_clear_pins()

    def on_enrolltoken_clicked(self, widget):
        self.builder.get_object('checkbuttonInitToken').set_active(self.CLIENTCONF['INITTOKEN'] == "True")
        self.builder.get_object('dialogEnroll').show()
        self.builder.get_object('frameTokenMOTP').hide()
        self.builder.get_object('frameTokenSPass').hide()
        self.builder.get_object('frameTokenOATH').hide()
        self.builder.get_object('frameTokenSMS').hide()
        self.builder.get_object('frameTokenYubikey').hide()
        self.builder.get_object('frameTokenRemote').hide()
        self.builder.get_object('frameTokenRadius').hide()
        self.builder.get_object('comboboxTokenType').set_active(0)
        self.builder.get_object('buttonEnrollOK').set_sensitive(True)
        self.gui_progressbarEnroll.set_fraction(0)
        self.gui_progressbarEnroll.set_text(_('Please insert token'))
        # evaluate the random PINs
        if (self.CLIENTCONF['RANDOMUSERPIN'] == 'True'):
            self.builder.get_object('labelEnrollUserPIN1').hide()
            self.builder.get_object('labelEnrollUserPIN2').hide()
            self.builder.get_object('entryEnrollUserPIN1').hide()
            self.builder.get_object('entryEnrollUserPIN2').hide()
        else:
            self.builder.get_object('labelEnrollUserPIN1').show()
            self.builder.get_object('labelEnrollUserPIN2').show()
            self.builder.get_object('entryEnrollUserPIN1').show()
            self.builder.get_object('entryEnrollUserPIN2').show()
        if (self.CLIENTCONF['RANDOMSOPIN'] == 'True'):
            self.builder.get_object('labelEnrollSOPIN1').hide()
            self.builder.get_object('labelEnrollSOPIN2').hide()
            self.builder.get_object('entryEnrollSOPIN1').hide()
            self.builder.get_object('entryEnrollSOPIN2').hide()
        else:
            self.builder.get_object('labelEnrollSOPIN1').show()
            self.builder.get_object('labelEnrollSOPIN2').show()
            self.builder.get_object('entryEnrollSOPIN1').show()
            self.builder.get_object('entryEnrollSOPIN2').show()


    def on_comboboxTokenType_changed(self, widget):
        ttype = self.builder.get_object('comboboxTokenType').get_active()
        # 0: eTokenNG OTP
        if (ttype == 0):
            self.builder.get_object('frameTokenETNG').show_all()
            self.builder.get_object('frameTokenMOTP').hide_all()
            self.builder.get_object('frameTokenOATH').hide_all()
            self.builder.get_object('frameTokenSPass').hide_all()
            self.builder.get_object('frameTokenSMS').hide_all()
            self.builder.get_object('frameTokenRemote').hide_all()
            self.builder.get_object('frameTokenYubikey').hide_all()
            self.builder.get_object('frameTokenRadius').hide_all()
        # 1: mOTP
        elif (ttype == 1):
            self.builder.get_object('frameTokenETNG').hide_all()
            self.builder.get_object('frameTokenMOTP').show_all()
            self.builder.get_object('frameTokenOATH').hide_all()
            self.builder.get_object('frameTokenSPass').hide_all()
            self.builder.get_object('frameTokenSMS').hide_all()
            self.builder.get_object('frameTokenRemote').hide_all()
            self.builder.get_object('frameTokenYubikey').hide_all()
            self.builder.get_object('frameTokenRadius').hide_all()
        #OATH
        elif (ttype == 2) or (ttype == 6):
            self.builder.get_object('frameTokenETNG').hide_all()
            self.builder.get_object('frameTokenMOTP').hide_all()
            self.builder.get_object('frameTokenOATH').show_all()
            self.builder.get_object('frameTokenSPass').hide_all()
            self.builder.get_object('frameTokenSMS').hide_all()
            self.builder.get_object('frameTokenRemote').hide_all()
            self.builder.get_object('frameTokenYubikey').hide_all()
            self.builder.get_object('frameTokenRadius').hide_all()
        #SPASS
        elif (ttype == 3):
            self.builder.get_object('frameTokenETNG').hide_all()
            self.builder.get_object('frameTokenMOTP').hide_all()
            self.builder.get_object('frameTokenOATH').hide_all()
            self.builder.get_object('frameTokenSPass').show_all()
            self.builder.get_object('frameTokenSMS').hide_all()
            self.builder.get_object('frameTokenRemote').hide_all()
            self.builder.get_object('frameTokenYubikey').hide_all()
            self.builder.get_object('frameTokenRadius').hide_all()
        # SMS
        elif (ttype == 4):
            self.builder.get_object('frameTokenETNG').hide_all()
            self.builder.get_object('frameTokenMOTP').hide_all()
            self.builder.get_object('frameTokenOATH').hide_all()
            self.builder.get_object('frameTokenSPass').hide_all()
            self.builder.get_object('frameTokenSMS').show_all()
            self.builder.get_object('frameTokenRemote').hide_all()
            self.builder.get_object('frameTokenYubikey').hide_all()
            self.builder.get_object('frameTokenRadius').hide_all()
            # preset the SMS phone number with number of user
            self.presetSMSphoneNumber()
        # yubikey
        elif (ttype == 5):
            self.builder.get_object('frameTokenETNG').hide_all()
            self.builder.get_object('frameTokenMOTP').hide_all()
            self.builder.get_object('frameTokenOATH').hide_all()
            self.builder.get_object('frameTokenSPass').hide_all()
            self.builder.get_object('frameTokenSMS').hide_all()
            self.builder.get_object('frameTokenRemote').hide_all()
            self.builder.get_object('frameTokenYubikey').show_all()
            self.builder.get_object('frameTokenRadius').hide_all()
        # remote
        elif (ttype == 7):
            self.builder.get_object('frameTokenETNG').hide_all()
            self.builder.get_object('frameTokenMOTP').hide_all()
            self.builder.get_object('frameTokenOATH').hide_all()
            self.builder.get_object('frameTokenSPass').hide_all()
            self.builder.get_object('frameTokenSMS').hide_all()
            self.builder.get_object('frameTokenRemote').show_all()
            self.builder.get_object('frameTokenYubikey').hide_all()
            self.builder.get_object('frameTokenRadius').hide_all()
        # radius
        elif (ttype == 8):
            self.builder.get_object('frameTokenETNG').hide_all()
            self.builder.get_object('frameTokenMOTP').hide_all()
            self.builder.get_object('frameTokenOATH').hide_all()
            self.builder.get_object('frameTokenSPass').hide_all()
            self.builder.get_object('frameTokenSMS').hide_all()
            self.builder.get_object('frameTokenRemote').hide_all()
            self.builder.get_object('frameTokenYubikey').hide_all()
            self.builder.get_object('frameTokenRadius').show_all()

##### Token resync

    def on_resynctoken_clicked(self, widget):
        serials = self.get_selected_serials()
        self.cr_serial = ""
        for self.cr_serial in serials:
            self.builder.get_object('entryResyncOTP1').set_text('')
            self.builder.get_object('entryResyncOTP2').set_text('')
            self.builder.get_object('dialogResync').show()
            self.builder.get_object('labelResyncToken').set_text(_("resyncing Token with serial: %s") % self.cr_serial)

    def on_buttonResyncOK_clicked(self, widget):
        otp1 = self.builder.get_object('entryResyncOTP1').get_text()
        otp2 = self.builder.get_object('entryResyncOTP2').get_text()
        try:
            rt = self.lotpclient.resynctoken({'serial':self.cr_serial,
                'otp1':otp1,
                'otp2':otp2})
            self.feedback(rt,
                _('Token with serial %s was resynchronized successfully') % self.cr_serial,
                _('Could not resyncronize Token with serial number %s') % self.cr_serial)
        except LinOTPClientError as e:
            self.popupError(e.getDescription())
            self.log.exception("token resync: %s" % e.getDescription)
        self.builder.get_object('dialogResync').hide()

    def on_buttonResyncCancel_clicked(self, widget):
        self.builder.get_object('dialogResync').hide()

    def on_tokenTreeview_button_press_event(self, widget, event):
        if event.button == 3:
            self.popupTokenMenu.popup(None, None, None, event.button, event.time)
            return True
        return False

    def on_userTreeview_button_press_event(self, widget, event):
        if event.button == 3:
            self.popupUserMenu.popup(None, None, None, event.button, event.time)
            return True
        return False

    def on_treeviewAudit_button_press_event(self, widget, event):
        if event.button == 3:
            print "treeview pressed"
            return True
        return False

###### Set OTP Pin Dialog

    def on_buttonSetpin_clicked(self, widget):
        self.builder.get_object('dialogSetpin').show()
        self.builder.get_object('buttonSetpinOK').set_sensitive(False)

    def on_buttonSetpinOK_clicked(self, widget):
        serials = self.get_selected_serials()
        pin = self.builder.get_object('entryPin1').get_text()
        try:
            for s in serials:
                rt = self.lotpclient.set({'serial':s, 'pin' : pin})
                self.feedback_set(rt, 'set pin',
                    _('OTP PIN of token %s set successfully') % s,
                    _('Could not set OTP PIN of token %s') % s)
        except LinOTPClientError as e:
            self.popupError(e.getDescription())
            self.log.exception("token set pin: %s" % e.getDescription)
        self.builder.get_object('dialogSetpin').hide()
        self.builder.get_object('entryPin1').set_text('')
        self.builder.get_object('entryPin2').set_text('')


    def on_buttonSetpinCancel_clicked(self, widget):
        self.builder.get_object('dialogSetpin').hide()
        self.builder.get_object('entryPin1').set_text('')
        self.builder.get_object('entryPin2').set_text('')

    def on_entryPin1_changed(self, widget):
        self.on_entryPin2_changed()

    def on_entryPin2_changed(self, widget):
        if self.builder.get_object('entryPin1').get_text() == self.builder.get_object('entryPin2').get_text():
            self.builder.get_object('labelSetpin').set_text(_('The OTP PINs are the same.'))
            self.builder.get_object('buttonSetpinOK').set_sensitive(True)
            self.builder.get_object('entryPin1').modify_base(gtk.STATE_NORMAL,
                gtk.gdk.color_parse("green"))
            self.builder.get_object('entryPin2').modify_base(gtk.STATE_NORMAL,
                gtk.gdk.color_parse("green"))
        else:
            self.builder.get_object('labelSetpin').set_text(_('The OTP PINs are different!'))
            self.builder.get_object('buttonSetpinOK').set_sensitive(False)
            self.builder.get_object('entryPin1').modify_base(gtk.STATE_NORMAL,
                gtk.gdk.color_parse("red"))
            self.builder.get_object('entryPin2').modify_base(gtk.STATE_NORMAL,
                gtk.gdk.color_parse("red"))

    def on_setMOTPpin(self, widget):
        self.builder.get_object('dialogSetMOTPPin').show()
        self.builder.get_object('buttonmOTPSetpinOK').set_sensitive(False)

    def on_motppinchanged(self, widget):
        if self.builder.get_object('entrymOTPPin1').get_text() == self.builder.get_object('entrymOTPPin2').get_text():
            self.builder.get_object('labelMOTPStatus').set_text(_('The mOTP PINs are the same.'))
            self.builder.get_object('buttonmOTPSetpinOK').set_sensitive(True)
            self.builder.get_object('entrymOTPPin1').modify_base(gtk.STATE_NORMAL,
                gtk.gdk.color_parse("green"))
            self.builder.get_object('entrymOTPPin2').modify_base(gtk.STATE_NORMAL,
                gtk.gdk.color_parse("green"))
        else:
            self.builder.get_object('labelMOTPStatus').set_text(_('The mOTP PINs are different!'))
            self.builder.get_object('buttonmOTPSetpinOK').set_sensitive(False)
            self.builder.get_object('entrymOTPPin1').modify_base(gtk.STATE_NORMAL,
                gtk.gdk.color_parse("red"))
            self.builder.get_object('entrymOTPPin2').modify_base(gtk.STATE_NORMAL,
                gtk.gdk.color_parse("red"))

    def on_buttonmOTPSetpinCancel_clicked(self, widget):
        self.builder.get_object('dialogSetMOTPPin').hide()
        self.builder.get_object('entrymOTPPin1').set_text('')
        self.builder.get_object('entrymOTPPin2').set_text('')

    def on_buttonmOTPSetpinOK_clicked(self, widget):
        serials = self.get_selected_serials()
        motppin = self.builder.get_object('entrymOTPPin1').get_text()
        try:
            for s in serials:
                rt = self.lotpclient.setscpin({'serial':s, 'userpin' : motppin})
                self.feedback_set(rt, 'set userpin',
                    _('mOTP PIN of token %s set successfully') % s,
                    _('Could not set mOTP PIN of token %s') % s)
        except LinOTPClientError as e:
            self.popupError(e.getDescription())
            self.log.exception("OTP set pin: %s" % e.getDescription)
        self.builder.get_object('dialogSetMOTPPin').hide()
        self.builder.get_object('entrymOTPPin1').set_text('')
        self.builder.get_object('entrymOTPPin2').set_text('')

    def on_entryfilter_changed(self, widget):
        # if the filter line is changed, we start to search:
        self.eTokenfilter = self.gui_entryFilter.get_text()
        # colorize the gtk.entry
        if (self.eTokenfilter != ""):
            self.gui_entryFilter.modify_base(gtk.STATE_NORMAL,
                gtk.gdk.color_parse(MARKCOLOR))
        else:
            self.gui_entryFilter.modify_base(gtk.STATE_NORMAL,
                gtk.gdk.color_parse("white"))

        self.setStatusLine(_("refiltering tokens"), 1)
        self.do_pulse()
        self.tokenfilter.refilter()
        self.setStatusLine(_("%s tokens managed") % self.numToken)


    def on_entryFilterUser_changed(self, widget):
        '''
        search the user while typing
        '''
        self.eUserfilter = self.gui_entryFilterUser.get_text()
        #self.do_pulse()
        if (self.eUserfilter != ""):
            self.gui_entryFilterUser.modify_base(gtk.STATE_NORMAL,
                gtk.gdk.color_parse(MARKCOLOR))
        else:
            self.gui_entryFilterUser.modify_base(gtk.STATE_NORMAL,
                gtk.gdk.color_parse("white"))

        self.gui_entryUser.set_text(self.eUserfilter)
        self.setStatusLine(_("refiltering users"), 2)
        self.userfilter.refilter()
        self.setStatusLine(_("%s users found") % self.numUser, 2)

    def on_entryUser_changed(self, widget):
        self.eUserfilter = self.builder.get_object('entryUser').get_text()
        self.builder.get_object('entryFilterUser').set_text(self.eUserfilter)

        self.setStatusLine(_("refiltering users"), 2)
        self.do_pulse()
        self.userfilter.refilter()
        self.setStatusLine(_("%s users found") % self.numUser, 2)

    def on_entryUserEnroll_changed(self, widget):
        self.eUserfilter = self.builder.get_object('entryEnrollUser').get_text()
        self.builder.get_object('entryFilterUser').set_text(self.eUserfilter)
        self.userfilter.refilter()

    def showUserinfo(self, widget, force=False):
        user = self.get_current_combobox_user('comboboxUser')
        if '' != user['loginname']:
            #self.builder.get_object('entryUser').set_text(user['loginname'])
            self.builder.get_object('labelUserinfoName').set_text(user['surname'] + ", " + user['givenname'] + " / " + user['resolver'])
            self.builder.get_object('labelUserinfoEmail').set_text(user['email'] + " : " + user['mobile'])

    def showUserinfoEnroll(self, widget, force=False):
        user = self.get_current_combobox_user('comboboxUserEnroll')
        if '' != user['loginname']:
            #self.builder.get_object('entryEnrollUser').set_text(user['loginname'])
            self.builder.get_object('labelUserinfoName1').set_text(str(user['surname']) + ", " + str(user['givenname']) + " / " + user['resolver'])
            self.builder.get_object('labelUserinfoEmail1').set_text(str(user['email']) + " : " + str(user['mobile']))
            self.presetSMSphoneNumber()

    def presetSMSphoneNumber(self):
        user = self.get_current_combobox_user('comboboxUserEnroll')
        if user.has_key('mobile'):
            self.builder.get_object('entrySMSPhone').set_text(user['mobile'])
        else:
            self.builder.get_object('entrySMSPhone').set_text("")

##### Configuration
    def on_imagemenuitemserverconfig_activate(self, widget):
        self.builder.get_object('spinbuttonSyncWindow').set_range(10, 1000)
        self.builder.get_object('spinbuttonOCRAmaxChallenge').set_range(1, 1000)
        self.builder.get_object('spinbuttonOTPLength').set_range(4, 10)
        self.builder.get_object('spinbuttonCountWindow').set_range(0, 100)
        self.builder.get_object('spinbuttonMaxFailCount').set_range(0, 100)
        self.builder.get_object('spinbuttonUidLDAPTimeout').set_range(1, 60)
        self.builder.get_object('checkbuttonSplitAtSign').set_active(True)
        # read config from the token database table Config.
        self.readServerConfig()
        try:
            for config, gui in self.serverConfigMapping.iteritems():
                if 'int' in gui:
                    guiElement = gui['int']
                    default = gui.get('default', 0)
                    config_value = self.serverConfig.get(config, default)
                    try:
                        self.builder.get_object(guiElement).set_value(float(config_value))
                    except TypeError:
                        self.builder.get_object(guiElement).set_value(0)
                        print "config_value <%s> for element %s is no float!" % (config_value, guiElement)
                elif 'text' in gui:
                    guiElement = gui['text']
                    try:
                        default = gui.get('default', "")
                        config_value = self.serverConfig.get(config) or default
                        self.builder.get_object(guiElement).set_text(config_value)
                    except TypeError as e:
                        print "%s: %s %s %s" % (str(e), guiElement, config, self.serverConfig[config])

                elif 'bool' in gui:
                    guiElement = gui['bool']
                    if config in self.serverConfig:
                        self.builder.get_object(guiElement).set_active(self.serverConfig[config] == "True")
            self.builder.get_object('dialogServerConfig').show()
            self.update_UserIdResolver_Treeview()
        except AttributeError as e:
            self.popupError (_("LinOTPGui::readServerConfig: %s") % e)
            self.log.exception("server config: %s" % e.getDescription)

    def create_useridresolvers_old(self):
        # Create new IdResolvers:
        # useridresolver: "useridresolver.PasswdIdResolver.IdResolver,useridresolver.LDAPIdResolver.IdResolver"
        # old, pre-Realm Stuff
        #aIdRes= []
        prefix = ""
        for instance, conf in self.resolverConfig.items():
            #if conf['active']==True:
            #    if conf['type']=="SQL":
            #        reso='useridresolver.SQLIdResolver.IdResolver.'+instance
            #        aIdRes.append( reso )
            #    elif conf['type']=="LDAP":
            #        reso='useridresolver.LDAPIdResolver.IdResolver.'+instance
            #        aIdRes.append( reso )
            #    elif conf['type']=="Flatfile":
            #        reso='useridresolver.PasswdIdResolver.IdResolver.'+instance
            #        aIdRes.append( reso )
            if conf['type'] == "SQL":
                prefix = "sqlresolver"
            elif conf['type'] == "LDAP":
                prefix = "ldapresolver"
            elif conf['type'] == "Flatfile":
                prefix = "passwdresolver"
            else:
                prefix = "Unknown_type_" + conf['type']
            # Now we do the config of the instance:
            for param, value in conf.items():
                # Do not store type and param
                if param != 'type' and param != 'active':
                    self.serverConfig[prefix + '.' + param + '.' + instance] = value
                    # CKO: Flat
                    #if conf['type']=="SQL" or conf['type']=="LDAP":
                    #    self.serverConfig[prefix+'.'+param+'.'+instance]=value
                    #else:
                    #    self.serverConfig[prefix+'.'+param]=value

        # FIXME: this stores the old configured resolvers. Remove this? We could also store the resolvers of the default REALM here...
        # CKO: 20100630 self.serverConfig['useridresolver'] = string.join(aIdRes,',')
        if self.serverConfig.has_key('useridresolver'):
            del self.serverConfig['useridresolver']

    def on_buttonServerConfigOK_clicked  (self, widget):
        try:
            for config, gui in self.serverConfigMapping.iteritems():
                if 'int' in gui:
                    guiElement = gui['int']
                    self.serverConfig[config] = str(int(self.builder.get_object(guiElement).get_value()))
                elif 'text' in gui:
                    guiElement = gui['text']
                    self.serverConfig[config] = self.builder.get_object(guiElement).get_text()
                elif 'bool' in gui:
                    guiElement = gui['bool']
                    self.serverConfig[config] = self.builder.get_object(guiElement).get_active()
            # Before we write the useridresolvers, we delete the old ones, without instance name!
            for key, value in self.serverConfig.items():
                if re.match("ldapresolver", key):
                    del self.serverConfig[key]
                elif re.match("sqlresolver", key):
                    del self.serverConfig[key]
            self.log.debug("[on_buttonServerConfigOK_clicked]: I will save this configuration to the server: %s" % pp.pformat(self.resolverConfig))

            #
            #self.create_uidresolvers_old()

            # write the rest of server config
            self.writeServerConfig()

            # TODO: We could wipe the LDAPBindPW here.
            self.readuser()
        except AttributeError as e:
            self.popupError (_("LinOTPGui::writeServerConfig: %s") % e)
            self.log.exception("server config activate: %s" % e.getDescription)
        self.builder.get_object('dialogServerConfig').hide()


    def on_entryUidLDAPURI_changed(self, widget):
        '''
        This function is called, when the URI of the LDAP resolver is changed.
        Then it is checked, if the URI starts with LDAPS, so the textarea for
        the CA certificate is displayed
        '''
        uri = self.builder.get_object('entryUidLDAPURI').get_text()
        if re.match("ldaps://", uri.lower()):
            self.builder.get_object('scrolledwindow_cacertificate').show()
            self.builder.get_object('label_cacertificate').show()
        else:
            self.builder.get_object('scrolledwindow_cacertificate').hide()
            self.builder.get_object('label_cacertificate').hide()


    def on_buttonUidOk_clicked(self, widget):
        uidtype = self.builder.get_object('comboboxUidRes').get_active()
        # Flatfile = 0, LDAP == 1, SQL == 2
        Config = {}
        if (uidtype == 0):
            Config["type"] = "Flatfile"
            Config["fileName"] = self.builder.get_object('entryUidPasswdFilename').get_text()
        elif (uidtype == 1):
            Config["type"] = "LDAP"
            Config["LDAPURI"] = self.builder.get_object('entryUidLDAPURI').get_text()
            Config["LDAPBASE"] = self.builder.get_object('entryUidLDAPBaseDN').get_text()
            Config["BINDDN"] = self.builder.get_object('entryUidLDAPBindDN').get_text()
            Config["BINDPW"] = self.builder.get_object('entryUidLDAPBindPW').get_text()
            Config["TIMEOUT"] = self.builder.get_object('spinbuttonUidLDAPTimeout').get_value()
            Config["LOGINNAMEATTRIBUTE"] = self.builder.get_object('entryUidLDAPAttrLogin').get_text()
            Config["LDAPFILTER"] = self.builder.get_object('entryUidLDAPAttrUserFilter').get_text()
            Config["LDAPSEARCHFILTER"] = self.builder.get_object('entryUidLDAPAttrSearchFilter').get_text()
            Config["USERINFO"] = self.builder.get_object('entryUidLDAPAttrMapping').get_text()
            Config["SIZELIMIT"] = self.builder.get_object('entryUidLDAPSizeLimit').get_text()
            Config["NOREFERRALS"] = self.builder.get_object('checkbuttonNoAnonymousReferralChasing').get_active()
            Config["UIDTYPE"] = self.builder.get_object('entryLDAPUidType').get_text()
            Config["CACERTIFICATE"] = self.builder.get_object('textview_cacertificate').get_buffer().get_text()
        elif (uidtype == 2):
            Config["type"] = "SQL"
            Config["Password"] = self.builder.get_object('entryUidSQLPassword').get_text()
            Config["Driver"] = self.builder.get_object('entryUidSQLDriver').get_text()
            Config["Map"] = self.builder.get_object('entryUidSQLMap').get_text()
            Config["Server"] = self.builder.get_object('entryUidSQLServer').get_text()
            Config["Table"] = self.builder.get_object('entryUidSQLTable').get_text()
            Config["User"] = self.builder.get_object('entryUidSQLUser').get_text()
            Config["Port"] = self.builder.get_object('entryUidSQLPort').get_text()
            Config["Database"] = self.builder.get_object('entryUidSQLDatabase').get_text()

        configname = self.builder.get_object('entryUidInstance').get_text()
        if configname:
            self.resolverConfig[configname] = Config
            self.update_UserIdResolver_Treeview()
            self.log.debug("[on_buttonUidOK_clicked]: set this userstore instance: %s" % pp.pformat(self.resolverConfig))

    def update_UserIdResolver_Treeview(self):
        '''
        Updates the Treeview of the configured UserIdResolvers
        '''
        self.builder.get_object('listofuserstores').clear()
        for name, config in self.resolverConfig.items():
            act = False
            self.builder.get_object('listofuserstores').append((act, config['type'], name, ''))

    def get_selected_uid(self):
        '''
        Returns the name of the selected UserIdResolver
        '''
        name = ''
        selected_uid = self.builder.get_object('treeviewUserstores').get_selection()
        uidstore, selected_rows = selected_uid.get_selected_rows()
        if (len(selected_rows) != 1):
            return ''
        else:
            for row in selected_rows:
                item = uidstore.get_iter_first()
                i = 0
                while (item != None):
                    if i == row[0]:
                        name = uidstore.get_value(item, 2)
                        break
                    i = i + 1
                    item = uidstore.iter_next(item)
            return name

    def on_treeviewUserstores_cursor_changed(self, widget):
        cUidName = self.get_selected_uid() or "Flatfile"
        # Fill the entry fields with self.resolverConfig[ cUidNmae
        Config = self.resolverConfig[ cUidName ]
        uidtype = Config["type"]

        self.builder.get_object('entryUidInstance').set_text(cUidName)

        if (uidtype == "Flatfile"):
            self.builder.get_object('comboboxUidRes').set_active(0)
            self.builder.get_object('framePasswdIdResolver').show()
            self.builder.get_object('frameLDAPIdResolver').hide()
            self.builder.get_object('frameSQLIdResolver').hide()
            self.builder.get_object('entryUidPasswdFilename').set_text(Config.get("fileName", ""))
        elif (uidtype == "LDAP"):
            self.builder.get_object('comboboxUidRes').set_active(1)
            self.builder.get_object('framePasswdIdResolver').hide()
            self.builder.get_object('frameLDAPIdResolver').show()
            self.builder.get_object('frameSQLIdResolver').hide()
            self.builder.get_object('entryUidLDAPURI').set_text(Config.get("LDAPURI", ""))
            self.builder.get_object('entryUidLDAPBaseDN').set_text(Config.get("LDAPBASE", ""))
            self.builder.get_object('entryUidLDAPBindDN').set_text(Config.get("BINDDN", ""))
            self.builder.get_object('entryUidLDAPBindPW').set_text(Config.get("BINDPW", ""))
            self.builder.get_object('spinbuttonUidLDAPTimeout').set_value(float(Config["TIMEOUT"]))
            self.builder.get_object('entryUidLDAPAttrLogin').set_text(Config.get("LOGINNAMEATTRIBUTE", ""))
            self.builder.get_object('entryLDAPUidType').set_text(Config.get("UIDTYPE") or "")
            self.builder.get_object('textview_cacertificate').get_buffer().set_text(Config.get("CACERTIFICATE") or "")
            self.builder.get_object('entryUidLDAPAttrUserFilter').set_text(Config.get("LDAPFILTER", ""))
            self.builder.get_object('entryUidLDAPAttrSearchFilter').set_text(Config.get("LDAPSEARCHFILTER", ""))
            self.builder.get_object('entryUidLDAPAttrMapping').set_text(Config.get("USERINFO", ""))
            self.builder.get_object('entryUidLDAPSizeLimit').set_text(Config.get('SIZELIMIT', ""))
            self.builder.get_object('checkbuttonNoAnonymousReferralChasing').set_active(Config.get('NOREFERRALS', 'False') == 'True')
        elif (uidtype == "SQL"):
            self.builder.get_object('comboboxUidRes').set_active(2)
            self.builder.get_object('framePasswdIdResolver').hide()
            self.builder.get_object('frameLDAPIdResolver').hide()
            self.builder.get_object('frameSQLIdResolver').show()
            self.builder.get_object('entryUidSQLPassword').set_text(Config.get("Password", ""))
            self.builder.get_object('entryUidSQLDriver').set_text(Config.get("Driver", ""))
            self.builder.get_object('entryUidSQLMap').set_text(Config.get("Map", ""))
            self.builder.get_object('entryUidSQLServer').set_text(Config.get("Server", ""))
            self.builder.get_object('entryUidSQLTable').set_text(Config.get("Table", ""))
            self.builder.get_object('entryUidSQLUser').set_text(Config.get("User", ""))
            self.builder.get_object('entryUidSQLPort').set_text(Config.get("Port", ""))
            self.builder.get_object('entryUidSQLDatabase').set_text(Config.get("Database", ""))

    def on_buttonUidDelete_clicked(self, widget):
        cUidName = self.get_selected_uid()
        del self.resolverConfig[ cUidName ]
        self.update_UserIdResolver_Treeview()
        if self.question_dialog(_("Do you really want to delete the UserIdResolver >>%s<<?" % cUidName)):
            r1 = self.lotpclient.deleteresolver({ 'resolver':cUidName})
            self.popupInfo(_("Please assure to remove the UserIdResolver >>%s<< from any realm definition!") % cUidName)
            #self.builder.get_object('treeviewUserstores').set_cursor(None)

    def on_buttonLDAPpresetLDAP_clicked(self, widget):
        self.builder.get_object('entryLDAPAttrLogin').set_text("uid")
        self.builder.get_object('entryLDAPAttrSearchFilter').set_text("(uid=*)(objectClass=inetOrgPerson)")
        self.builder.get_object('entryLDAPAttrUserFilter').set_text("(&(uid=%s)(objectClass=inetOrgPerson))")
        self.builder.get_object('entryLDAPUidType').set_text("entryUUID")
        self.builder.get_object('entryLDAPAttrMapping').set_text('{ "username": "uid", "phone" : "telephoneNumber", "mobile" : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" }')

    def on_buttonLDAPpresetAD_clicked(self, widget):
        self.builder.get_object('entryLDAPUidType').set_text("objectGUID")
        self.builder.get_object('entryLDAPAttrLogin').set_text("sAMAccountName")
        self.builder.get_object('entryLDAPAttrSearchFilter').set_text("(sAMAccountName=*)(objectClass=user)")
        self.builder.get_object('entryLDAPAttrUserFilter').set_text("(&(sAMAccountName=%s)(objectClass=user))")
        self.builder.get_object('entryLDAPAttrMapping').set_text('{ "username": "sAMAccountName", "phone" : "telephoneNumber", "mobile" : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" }')

    def on_buttonLDAPpresetNovell_clicked(self, widget):
        self.builder.get_object('entryLDAPUidType').set_text("GUID")
        self.builder.get_object('entryLDAPAttrLogin').set_text("uid")
        self.builder.get_object('entryLDAPAttrSearchFilter').set_text("(uid=*)(objectClass=inetOrgPerson)")
        self.builder.get_object('entryLDAPAttrUserFilter').set_text("(&(uid=%s)(objectClass=inetOrgPerson))")
        self.builder.get_object('entryLDAPAttrMapping').set_text('{ "username":"uid", "phone": "homePhone", "mobile": "mobile", "email": "mail", "surname": "sn", "givenname": "givenName"}')

    def on_buttonLDAPpresetLDAP1_clicked(self, widget):
        self.builder.get_object('entryLDAPUidType').set_text("entryUUID")
        self.builder.get_object('entryUidLDAPAttrLogin').set_text("uid")
        self.builder.get_object('entryUidLDAPAttrSearchFilter').set_text("(uid=*)(objectClass=inetOrgPerson)")
        self.builder.get_object('entryUidLDAPAttrUserFilter').set_text("(&(uid=%s)(objectClass=inetOrgPerson))")
        self.builder.get_object('entryUidLDAPAttrMapping').set_text('{ "username": "uid", "phone" : "telephoneNumber", "mobile" : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" }')

    def on_buttonLDAPpresetAD1_clicked(self, widget):
        self.builder.get_object('entryLDAPUidType').set_text("objectGUID")
        self.builder.get_object('entryUidLDAPAttrLogin').set_text("sAMAccountName")
        self.builder.get_object('entryUidLDAPAttrSearchFilter').set_text("(sAMAccountName=*)(objectClass=user)")
        self.builder.get_object('entryUidLDAPAttrUserFilter').set_text("(&(sAMAccountName=%s)(objectClass=user))")
        self.builder.get_object('entryUidLDAPAttrMapping').set_text('{ "username": "sAMAccountName", "phone" : "telephoneNumber", "mobile" : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" }')

    def on_buttonLDAPpresetNovell1_clicked(self, widget):
        self.builder.get_object('entryLDAPUidType').set_text("GUID")
        self.builder.get_object('entryUidLDAPAttrLogin').set_text("uid")
        self.builder.get_object('entryUidLDAPAttrSearchFilter').set_text("(uid=*)(objectClass=inetOrgPerson)")
        self.builder.get_object('entryUidLDAPAttrUserFilter').set_text("(&(uid=%s)(objectClass=inetOrgPerson))")
        self.builder.get_object('entryUidLDAPAttrMapping').set_text('{ "username":"uid", "phone": "homePhone", "mobile": "mobile", "email": "mail", "surname": "sn", "givenname": "givenName"}')

    def on_buttonTestLDAP_clicked(self, widget):
        # read the contents of the inputs and issue
        # /admin/testresolver?type=ldap
        p = {}
        p['type'] = 'ldap'
        p['ldap_uri'] = self.builder.get_object('entryUidLDAPURI').get_text()
        p['ldap_basedn'] = self.builder.get_object('entryUidLDAPBaseDN').get_text()
        p['ldap_binddn'] = self.builder.get_object('entryUidLDAPBindDN').get_text()
        p['ldap_password'] = self.builder.get_object('entryUidLDAPBindPW').get_text()
        p['ldap_timeout'] = self.builder.get_object('spinbuttonUidLDAPTimeout').get_value_as_int()
        p['ldap_loginattr'] = self.builder.get_object('entryUidLDAPAttrLogin').get_text()
        p['ldap_searchfilter'] = self.builder.get_object('entryUidLDAPAttrSearchFilter').get_text()
        p['ldap_userfilter'] = self.builder.get_object('entryUidLDAPAttrUserFilter').get_text()
        p['ldap_mapping'] = self.builder.get_object('entryUidLDAPAttrMapping').get_text()
        p['ldap_sizelimit'] = self.builder.get_object('entryUidLDAPSizeLimit').get_text()
        p['NOREFERRALS'] = self.builder.get_object('checkbuttonNoAnonymousReferralChasing').get_active()
        try:
            ret = self.lotpclient.connect('/admin/testresolver', p)
            if (ret['result']['status']):
                result = ret['result']['value']['result']
                if (result == "success"):
                    userarray = ret['result']['value']['desc']
                    self.popupInfo("Success. You configuration seems to be ok. %i users found." % len(userarray))
                else:
                    self.popupError(ret['result']['value']['desc'])
            else:
                self.popupError(ret['result']['error']['message'])
        except LinOTPClientError as e:
            self.popupError("Error testing LDAP connection: %s" % e.getDescription())


#### REALM config


    def on_buttonRemoveRealm_clicked(self, widget):
        (model, iter) = self.builder.get_object('treeviewRealm').get_selection().get_selected()
        if iter != None:
            parent = model.iter_parent(iter)
            # this is a top level (realm)
            if None is parent:
                realmname = self.obj_treestoreRealm.get(iter, 1)[0]
                self.obj_treestoreRealm.remove(iter)
                realmstore = self.builder.get_object('realmstore')
                aiter = realmstore.get_iter_first()
                while None is not aiter:
                    if realmstore.get(aiter, 1)[0] == realmname:
                        realmstore.remove(aiter)
                        break
                    aiter = realmstore.iter_next(aiter)


    def on_buttonAddRealm_clicked(self, widget):
        self.builder.get_object('dialogEditRealm').show()
        self.builder.get_object('labelEditRealm').set_text(_('Add realm with the following name:'))
        self.builder.get_object('entryEditRealm').set_text('')

    def on_buttonEditRealmOK_clicked(self, widget):
        new_realm = self.builder.get_object('entryEditRealm').get_text().lower()
        if (not re.match("^[0-9a-zA-Z\-]+$", new_realm)):
            self.popupInfo(_('The realm should only consist of the characters a-zA-Z0-9 and minus: "-"'))
        else:
            # check if realm already exists
            if self.insert_realm(new_realm) != None:
                self.builder.get_object('dialogEditRealm').hide()
                self.builder.get_object('realmstore').append((new_realm, new_realm))
            else:
                self.popupInfo(_("The REALM %s already exists!") % new_realm)
            for i in self.realmConfig.items():
                print i

    def on_buttonEditRealmCancel_clicked(self, widget):
        self.builder.get_object('dialogEditRealm').hide()

    def on_buttonAddUserstoreToRealm_clicked(self, widget):
        aiter = self.builder.get_object('comboboxUserstores').get_active_iter()
        if aiter:
            userstore = self.builder.get_object('listofuserstores').get(aiter, 2)[0]
            # Add this userstore to the selected REALM
            (model, iter) = self.builder.get_object('treeviewRealm').get_selection().get_selected()
            # Only add, if the selection is toplevel
            # i.e.: has no parent
            if None is model.iter_parent(iter):
                # check if userstore already exist in this realm
                entry_found = False
                numChildren = model.iter_n_children(iter)
                for i in range(numChildren):
                    # check in all child entries:
                    # model.iter_nth_child(iter,i): i-te child of REALM=iter
                    # ,1 : This is the 2nd column...
                    entry = model.get_value(model.iter_nth_child(iter, i) , 1)
                    if entry.upper() == userstore.upper():
                        entry_found = True
                        break
                if not entry_found:
                    self.obj_treestoreRealm.append(iter, (0, userstore))
            else:
                self.popupError(_("Please select a realm."))

    def on_buttonRemoveUserstoreFromRealm_clicked(self, widget):
        # get the current selection:
        (model, iter) = self.builder.get_object('treeviewRealm').get_selection().get_selected()
        if iter != None:
            parent = model.iter_parent(iter)
            if None is not parent:
                self.obj_treestoreRealm.remove(iter)
                #model.remove(iter)
                if 0 == model.iter_n_children(parent):
                    self.popupInfo(_("You should also delete this empty realm. An empty realm can not be stored to the LinOTP server."))

    def writeServerConfigRealm(self):
        '''
        This function is called, when the serverConfig is about to be written to the server.
        It writes the configuration of the realms to the server using the following functions:
            lotpclient.setrealm ( { realm:"...", "resolvers":"....."} )
            lotpclient.setdefaultrealm ( { realm:<defaultrealm> } )
        '''
        new_realms = []
        store = self.obj_treestoreRealm
        iter = store.get_iter_first()
        while iter != None:
            realm = store.get(iter, 1)[0]
            new_realms.append(realm.lower())
            resolvers = ""
            citer = store.iter_children(iter)
            while citer != None:
                res_instance = store.get(citer, 1)[0]
                # add to the value: 'useridresolver.LDAPIdResolver.IdResolver.'+store.get(citer, 1)[0]
                idres = self.get_type_of_res_instance(res_instance)
                resolvers += idres
                citer = store.iter_next(citer)
                if citer != None:
                    resolvers += ','
            iter = store.iter_next(iter)
            try:
                self.log.debug("writeServerConfigRealm: about to save %s:%s" % (realm, resolvers))
                self.lotpclient.setrealm({ 'realm':realm, 'resolvers':resolvers })
            except LinOTPClientError as e:
                self.popupError("Error saving realm >%s<: %s" % (realm, e.getDescription()))
            self.log.debug("writeServerConfigRealm: saved: %s:%s" % (realm, resolvers))

        # delete realms, that are to be deleted
        for (realm, realmconfig) in self.realmConfig.items():
            if 0 == new_realms.count(realm.lower()):
                try:
                    self.log.debug("writeServerConfigRealm: about to delete realm: %s" % realm)
                    self.lotpclient.deleterealm({'realm':realm.lower() })
                except LinOTPClientError as e:
                    self.log.error("writeServerConfigRealm: delete realm %s failed.")
                    self.popupError("Error deleting realm >%s<: %s" % (realm, e.getDescription()))

        # set default realm
        try:
            aiter = self.builder.get_object('comboboxDefaultRealm').get_active_iter()
            aindex = self.builder.get_object('comboboxDefaultRealm').get_active()
            if aiter and aindex > 0:
                defaultrealm = self.builder.get_object('realmstore').get(aiter, 0)[0]
                self.log.debug("writeServerConfigRealm: about to set default realm: %s" % realm)
                self.lotpclient.setdefaultrealm({ 'realm': defaultrealm })
            else:
                # No default Realm!
                self.lotpclient.setdefaultrealm({})
        except LinOTPClientError as e:
            self.popupError(e.getDescription())

    def insert_realm(self, new_realm):
        '''
        adds a new realm to the treestore Realm.
        It also takes care, to not add two of the same entries.
        '''
        entry_found = False
        for i in range(len(self.obj_treestoreRealm)):
            # check in all top level entries:
            entry = self.obj_treestoreRealm[i - 1][1]
            if entry.upper() == new_realm.upper():
                entry_found = True
                break
        if not entry_found:
            new_iter = self.obj_treestoreRealm.append(None, (0, new_realm))
            return new_iter
        else:
            return None

    def fill_comboboxrealm(self):
        '''
        This function fills the combobox RealmSearch with all valid
        realm. This is for the userview.
        '''
        self.setStatusLine(_("Reading realms"), 2)
        realmstore2 = self.builder.get_object('realmstore2')
        realmstore3 = self.builder.get_object('realmstore3')
        realmstore_getserial = self.builder.get_object('realmstore_getserial')
        realmstore2.clear()
        realmstore3.clear()
        realmstore2.append(("*", _(">> all realms <<")))
        realmstore_getserial.append(("", ""))
        for realmkey, realm in self.realmConfig.items():
            realmstore_getserial.append((realmkey, realm['realmname']))
            realmstore2.append((realmkey, realm['realmname']))
            realmstore3.append((False, realm['realmname']))



    def fill_treestoreRealm(self):
        '''
        This completely fills the treestoreRealm
        and also the realmstore, that is used to select
        the default realm
        '''
        treestore = self.obj_treestoreRealm
        realmstore = self.builder.get_object('realmstore')
        realmstore.clear()
        aiter = realmstore.append((_("No default realm"), _("No default realm")))
        self.builder.get_object('comboboxDefaultRealm').set_active_iter(aiter)
        treestore.clear()
        for realmkey, realm in self.realmConfig.items():
            aiter = realmstore.append((realmkey, realm['realmname']))

            if realm.has_key('default'):
                if "true" == realm['default']:
                    self.builder.get_object('comboboxDefaultRealm').set_active_iter(aiter)

            realm_iter = self.insert_realm(realm['realmname'])
            if None != realm_iter:
                for res in realm['useridresolver']:
                    (type, name) = self.get_resolver_info(res)
                    if "" != name:
                        treestore.append(realm_iter, (0, name))


    def get_resolver_info(self, resolver):
        '''
        description: This function returns the name and the type of a resolver
        params:
            resolver:   string like: useridresolver.PasswdIdResolver.IdResolver
                        or: useridresolver.LDAPIdResolver.IdResolver.REALM1
        returns:
            (type, name) tuple,
                type : SQL / LDAP / Flatfile
                name:  _default_Passwd_ or REALM1
        '''
        defaultNames = { 'SQL': "_default_SQL_",
                        'LDAP': "_default_LDAP_",
                        'Flatfile': "_default_Passwd_" }
        type = ""
        name = ""
        a = resolver.rsplit('.')

        # FIXME: Do we really need to transform this?
        if len(a) >= 2:
            if "SQLIdResolver" == a[1]:
                type = "SQL"
            elif "PasswdIdResolver" == a[1]:
                type = "Flatfile"
            elif "LDAPIdResolver" == a[1]:
                type = "LDAP"

        if len(a) == 3:
            name = defaultNames[type]
        elif len(a) == 4:
            name = a[3]
        return (type, name)

    def get_type_of_res_instance(self, instance):
        '''
        This function takes the name of a resolver instance and returns the type for it.
        '''
        #useridresolver.LDAPIdResolver.IdResolver._default_LDAP_
        type = ""
        ret = ""
        store = self.builder.get_object('listofuserstores')
        iter = store.get_iter_first()
        while iter != None:
            #print store.get(iter,2), store.get(iter,1)
            if instance == store.get(iter, 2)[0]:
                type = store.get(iter, 1)[0]
                break
            iter = store.iter_next(iter)
        if "LDAP" == type:
            ret = "useridresolver.LDAPIdResolver.IdResolver." + instance
        elif "SQL" == type:
            ret = "useridresolver.SQLIdResolver.IdResolver." + instance
        elif "Flatfile" == type:
            ret = "useridresolver.PasswdIdResolver.IdResolver." + instance
        return ret


#### Client Config


    def on_imagemenuitemclientconfig_activate(self, widget):
        self.builder.get_object('entryConnectionServer').set_text(self.CLIENTCONF['HOSTNAME'])
        if self.CLIENTCONF['PROTOCOL'] == "https":
            proto = 1
            self.builder.get_object('entryClientCert').set_sensitive(True)
            self.builder.get_object('entryClientKey').set_sensitive(True)
        else:
            proto = 0
            self.builder.get_object('entryClientCert').set_sensitive(False)
            self.builder.get_object('entryClientKey').set_sensitive(False)
        self.builder.get_object('comboboxConnectionProtocol').set_active(proto)
        self.builder.get_object('spinbuttonConnectionPort').set_range(0, 65536)
        self.builder.get_object('spinbuttonConnectionPort').set_value(int(self.CLIENTCONF['PORT']))
        self.builder.get_object('entryUIFile').set_text(self.CLIENTCONF['UIFILE'])
        self.builder.get_object('entryDefaultTokenName').set_text(self.CLIENTCONF['DEFAULTTOKENNAME'])
        self.builder.get_object('spinbuttonPasswordRetry').set_range(1, 15)
        self.builder.get_object('spinbuttonPasswordRetry').set_value(int(self.CLIENTCONF['RETRYCOUNTER']))
        self.builder.get_object('spinbuttonDisplayDuration').set_range(5, 30)
        self.builder.get_object('spinbuttonDisplayDuration').set_value(int(self.CLIENTCONF['DISPLAYDURATION']))
        self.builder.get_object('entryClientCert').set_text(self.CLIENTCONF['CLIENTCERT'])
        self.builder.get_object('entryClientKey').set_text(self.CLIENTCONF['CLIENTKEY'])
        self.builder.get_object('entryProxy').set_text(self.CLIENTCONF['PROXY'])
        self.builder.get_object('dialogClientConfig').show()
        self.builder.get_object('checkbuttonRandomUserPIN').set_active(self.CLIENTCONF['RANDOMUSERPIN'] == 'True')
        self.builder.get_object('checkbuttonRandomSOPIN').set_active(self.CLIENTCONF['RANDOMSOPIN'] == 'True')
        self.builder.get_object('checkbuttonInitTokenDefault').set_active(self.CLIENTCONF['INITTOKEN'] == 'True')
        self.builder.get_object('checkbuttonClearUserFilter').set_active(self.CLIENTCONF['CLEARUSERFILTER'] == 'True')
        if ("Digest" == self.CLIENTCONF['AUTHTYPE']):
            self.builder.get_object('comboboxAuthtype').set_active(0)
        else:
            self.builder.get_object('comboboxAuthtype').set_active(1)

        self.builder.get_object('spinbuttonLogCount').set_range(1, 30)
        self.builder.get_object('spinbuttonLogCount').set_value(int(self.CLIENTCONF['LOGCOUNT']))
        self.builder.get_object('spinbuttonLogSize').set_range(1024, 100 * 1024 * 1024)
        self.builder.get_object('spinbuttonLogSize').set_value(int(self.CLIENTCONF['LOGSIZE']))
        self.builder.get_object('entryLogFile').set_text(self.CLIENTCONF['LOGFILE'])
        self.builder.get_object('comboboxLogLevel').set_active(int(self.CLIENTCONF['LOGLEVEL']))

    def on_comboboxConnectionProtocol_changed(self, widget):
        if (self.builder.get_object('comboboxConnectionProtocol').get_active() == 1):
            self.builder.get_object('entryClientCert').set_sensitive(True)
            self.builder.get_object('entryClientKey').set_sensitive(True)
        else:
            self.builder.get_object('entryClientCert').set_sensitive(False)
            self.builder.get_object('entryClientKey').set_sensitive(False)
            self.builder.get_object('entryClientCert').set_text('')
            self.builder.get_object('entryClientKey').set_text('')

    def on_comboboxUidRes_changed(self, widget):
        uidtype = self.builder.get_object('comboboxUidRes').get_active()
        self.builder.get_object('entryUidInstance').set_sensitive(True)
        if (uidtype == 0):  # 0 == Flatfile
            self.builder.get_object('framePasswdIdResolver').show()
            self.builder.get_object('frameLDAPIdResolver').hide()
            self.builder.get_object('frameSQLIdResolver').hide()
            #self.builder.get_object('entryUidInstance').set_text("_default_Passwd_")
        elif (uidtype == 1):  # 1 == LDAP
            self.builder.get_object('framePasswdIdResolver').hide()
            self.builder.get_object('frameLDAPIdResolver').show()
            self.builder.get_object('frameSQLIdResolver').hide()
            #self.builder.get_object('entryUidInstance').set_text("_default_LDAP_")
        elif (uidtype == 2):  # 2 == SQL
            self.builder.get_object('framePasswdIdResolver').hide()
            self.builder.get_object('frameLDAPIdResolver').hide()
            self.builder.get_object('frameSQLIdResolver').show()

    def on_comboboxSearchRealm_changed(self, widget):
        '''
        This method is called, when the Realm combobox is changed.
        Than the userlist is loaded anew
        '''
        self.readuser()


    def on_buttonClientConfigOK_clicked(self, widget):
        self.CLIENTCONF['HOSTNAME'] = self.builder.get_object('entryConnectionServer').get_text()
        proto = self.builder.get_object('comboboxConnectionProtocol').get_active()
        if proto == 1:
            self.CLIENTCONF['PROTOCOL'] = "https"
        else:
            self.CLIENTCONF['PROTOCOL'] = "http"
        self.CLIENTCONF['PORT'] = self.builder.get_object('spinbuttonConnectionPort').get_value_as_int()
        self.CLIENTCONF['UIFILE'] = self.builder.get_object('entryUIFile').get_text()
        self.CLIENTCONF['DEFAULTTOKENNAME'] = self.builder.get_object('entryDefaultTokenName').get_text()
        self.CLIENTCONF['RETRYCOUNTER'] = self.builder.get_object('spinbuttonPasswordRetry').get_value_as_int()
        self.CLIENTCONF['DISPLAYDURATION'] = self.builder.get_object('spinbuttonDisplayDuration').get_value_as_int()
        self.CLIENTCONF['CLIENTCERT'] = self.builder.get_object('entryClientCert').get_text()
        self.CLIENTCONF['CLIENTKEY'] = self.builder.get_object('entryClientKey').get_text()
        self.CLIENTCONF['PROXY'] = self.builder.get_object('entryProxy').get_text()
        self.CLIENTCONF['RANDOMUSERPIN'] = str(self.builder.get_object('checkbuttonRandomUserPIN').get_active())
        self.CLIENTCONF['INITTOKEN'] = str(self.builder.get_object('checkbuttonInitTokenDefault').get_active())
        self.CLIENTCONF['RANDOMSOPIN'] = str(self.builder.get_object('checkbuttonRandomSOPIN').get_active())
        self.CLIENTCONF['LOGFILE'] = self.builder.get_object('entryLogFile').get_text()
        self.CLIENTCONF['LOGCOUNT'] = self.builder.get_object('spinbuttonLogCount').get_value_as_int()
        self.CLIENTCONF['LOGSIZE'] = self.builder.get_object('spinbuttonLogSize').get_value_as_int()
        self.CLIENTCONF['LOGLEVEL'] = str(self.builder.get_object('comboboxLogLevel').get_active())
        self.CLIENTCONF['CLEARUSERFILTER'] = str(self.builder.get_object('checkbuttonClearUserFilter').get_active())
        self.CLIENTCONF['AUTHTYPE'] = str(self.builder.get_object('comboboxAuthtype').get_active_text())
        self.writeClientConfig(self)
        self.builder.get_object('dialogClientConfig').hide()
        self.CLIENTCONF['URL'] = self.CLIENTCONF['HOSTNAME'] + ":" + str(self.CLIENTCONF['PORT'])
        self.readtoken()
        self.readuser()


    def on_comboboxLogLevel_changed(self, widget):
        if self.builder.get_object('comboboxLogLevel').get_active() == 0:
            self.popupInfo(_("Please note: When choosing DEBUG log level passwords and other credentials get written to the logfile!"))

    def on_buttonClientConfigCancel_clicked(self, widget):
        self.builder.get_object('dialogClientConfig').hide()

    def on_buttonServerConfigCancel_clicked  (self, widget):
        self.builder.get_object('dialogServerConfig').hide()

    def loginLinOTPServer(self, widget):
        self.builder.get_object('labelLoginWelcome').set_text(_("Login to %s") % self.CLIENTCONF['URL'])
        self.builder.get_object('dialogLogin').show()

    def on_buttonLoginOK_clicked(self, widget):
        self.builder.get_object('dialogLogin').hide()
        self.setStatusLine(_("Logging in to LinOTP server..."))

        self.CLIENTCONF['ADMIN'] = self.builder.get_object('entryLoginUsername').get_text()
        self.CLIENTCONF['ADMINPW'] = self.builder.get_object('entryLoginPassword').get_text()
        self.CLIENTCONF['URL'] = "{0}:{1}".format(self.CLIENTCONF['HOSTNAME'], self.CLIENTCONF['PORT'])
        try:
            self.lotpclient.setcredentials(self.CLIENTCONF['PROTOCOL'], self.CLIENTCONF['URL'],
                                            self.CLIENTCONF['ADMIN'], self.CLIENTCONF['ADMINPW'],
                                            self.CLIENTCONF['CLIENTCERT'], self.CLIENTCONF['CLIENTKEY'],
                                            self.CLIENTCONF['PROXY'], self.CLIENTCONF['AUTHTYPE'])
        except LinOTPClientError as e:
            self.popupError(str(e))
        self.builder.get_object('entryLoginUsername').set_text('')
        self.builder.get_object('entryLoginPassword').set_text('')

        self.readServerConfig()

        self.builder.get_object('statusLabelLoggedIn').set_text(
            _('Logged in as') + ': ' + self.CLIENTCONF['ADMIN'] + '@' + self.CLIENTCONF['URL'])

        '''
        try:
            rv = self.lotpclient.readserverconfig(  {} )
            if rv['result']['status'] == True:
                self.serverConfig=rv['result']['value']

            rv = self.lotpclient.getrealms( {} )
            if rv['result']['status'] == True:
                self.realmConfig=rv['result']['value']
        except LinOTPClientError as e:
            if e.getId() in [1005, 1006]:
                self.loginLinOTPServer(self)
            else:
                self.popupError( _("Error reading configuration from server: %s") % e.getDescription() )
            self.log.exception( "readServerConfig: %s" % e.getDescription )
        '''
        self.fill_comboboxrealm()
        self.readtoken()
        self.readuser()

    def on_buttonLoginCancel_clicked(self, widget):
        self.builder.get_object('dialogLogin').hide()

#### Token View functions

    def on_buttonTokenPageFirst_clicked(self, widget):
        if self.tokenpage > 0:
            self.tokenpage = 0
            self.readtoken()

    def on_buttonTokenPagePrev_clicked(self, widget):
        if self.tokenpage > 1:
            self.tokenpage -= 1
            self.readtoken()

    def on_buttonTokenPageNext_clicked(self, widget):
        if self.tokenpage < self.tokenpagenum:
            self.tokenpage += 1
            self.readtoken()

    def on_buttonTokenPageLast_clicked(self, widget):
        if self.tokenpage < self.tokenpagenum:
            self.tokenpage = self.tokenpagenum
            self.readtoken()


    def setTreeviewTokenActive(self, widget, value):
        #self.popupError( "Token toggeled" )
        print value

    def toggleTokenRealm(self, widget, value):
        realmstore = self.builder.get_object('realmstore3')
        # realmstore[value] is a treemodelrow
        realmstore[value][0] = not realmstore[value][0]

    def onTokenRealm(self, widget):
        self.builder.get_object('dialogTokenRealm').show()

    def on_buttonTokenRealmCancel_clicked(self, widget):
        self.builder.get_object('dialogTokenRealm').hide()

    def on_buttonTokenRealmOK_clicked(self, widget):
        serials = self.get_selected_serials()
        realmstore = self.builder.get_object('realmstore3')
        realms = []
        for row in realmstore:
            if row[0]:
                realms.append(row[1])
        realmsStr = ','.join(realms)

        try:
            for serial in serials:
                rv = self.lotpclient.tokenrealm(serial, realmsStr)
                if rv['result']['status'] == False:
                    self.popupError(_("Could not set the realms of token %s:") %
                    (serial, rv['result']['error']['message']))
            self.builder.get_object('dialogTokenRealm').hide()
            self.readtoken()
        except LinOTPClientError as e:
            if e.getId() == e.getId() in [1005, 1006]:
                self.loginLinOTPServer(self)
            else:
                self.popupError(_("Could not set the token realms: %s") % e.getDescription())
            self.log.exception("setTokenRealm: %s" % e.getDescription)


##### License

    def license_get(self):
        '''
            reads the license information from the server.
            Error codes:
                ret: error retrieving license from the server
                exc: Token number exceeded
                sig: Signature failure
                nol: no license found
        '''
        try:
            licret = self.lotpclient.connect('/system/getSupportInfo', {})
        except Exception as exx:
            self.popupInfo("This version of admin client is intended to manage "
                           "the LinOTP open source edition. The LinOTP server "
                           "you are trying to administer is probably too old "
                           "and does not support the API call "
                           "/system/getSupportInfo")
            licret = self.lotpclient.connect('/license/getLicense', {})

        licres = licret['result']
        error = { 'ret':0, 'exc':0, 'sig':0, 'nol':0 }
        errorSum = 0
        errorString = ""
        if licres['status'] == True:
            if 'license' in licres['value'] and 'license' in licres['value']['license']:
                LICENSE = licres['value']['license']
                self.log.debug("[license_get]: The license is of type %s" % type(LICENSE))
                self.lic.setlicense(str(LICENSE))
                self.log.debug("[license_get()]: %s" % LICENSE)
                error['sig'] = 0
            elif licres.get('value', {}).get('description', None) is not None:
                LICENSE = licres['value']['description']
                self.log.debug("[license_get]: The license is of type %s" % type(LICENSE))
                self.lic.licDict = {}
                self.lic.setlicense(str(LICENSE))
                if len(self.lic.licDict) == 0:
                    self.lic.licDict = LICENSE
                self.log.debug("[license_get()]: %r" % LICENSE)
                error['sig'] = 0
            else:
                error['nol'] = 1
        else:
            error['ret'] = 1


        self.gui_statusLabelLicense.set_text(_('Community Supported'))

        if 0 == error['sig']:
            tokens = self.lic.getTokenNum()
            if type(tokens) in [int]:
                tokenstring = " %s " % self.lic.getTokenNum() + _("tokens")
                self.gui_statusLabelLicense.set_text(self.lic.getlicensee() + ", " + tokenstring)

        # collect all errors
        for k, v in error.items():
            errorSum += v

        if errorSum != 0:
            # Display licensing errors
            if error['sig']:
                errorString += _("Signature-Error: The license information that was retrieved, was invalid!\n")
            if error['ret']:
                errorString += _("License-Error: The license information could not be retrieved from the server!\n")
            if error['exc']:
                errorString += _("Licensing-Error: Your tokens in use exceed the licensed token numbers. Please upgrade your license!\n")
            if error['nol']:
                errorString += _("Licensing-Error: You are running without a license!\n")

            if 'nol' not in error:
                self.popupError(errorString)
            self.log.debug(errorString)


    def on_menuitemlicense_activate(self, widget):
        '''
            Open the license dialog
        '''
        self.builder.get_object('dialogLicense').show()
        # verify the license
        self.license_get()
        # display the license...
        self.license_show()

    def on_buttonLicClose_clicked(self, widget):
        '''
            Close the license dialog
        '''
        self.builder.get_object('dialogLicense').hide()

    def on_buttonSetLicense_clicked(self, widget):
        '''
            Open a filechoose to select a license and
            upload this license to the server
        '''
        license_filename = ""
        dialog = gtk.FileChooserDialog(_("Select license file"),
            None,
            gtk.FILE_CHOOSER_ACTION_OPEN,
            (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
            gtk.STOCK_OPEN, gtk.RESPONSE_OK))
        dialog.set_default_response(gtk.RESPONSE_OK)
        filter = gtk.FileFilter()
        filter.set_name(_("license file"))
        filter.add_pattern("*.pem")
        filter.add_pattern("*.lic")
        dialog.add_filter(filter)
        filter = gtk.FileFilter()
        filter.set_name(_("All files"))
        filter.add_pattern("*")
        dialog.add_filter(filter)
        response = dialog.run()
        licret = {}
        if response == gtk.RESPONSE_OK:
            license_filename = dialog.get_filename()
            dialog.destroy()
            try:
                f = open(license_filename, 'r')
                file_contents = f.read()
                f.close()
                self.log.debug("[on_buttonSetLicense_clicked]: reading license from file: >>>%s<<<" % file_contents)
                self.log.debug("[on_buttonSetLicense_clicked]: license of type %s" % type(file_contents))
                file_contents = unicode(file_contents)
                self.log.debug("[on_buttonSetLicense_clicked]: setting to unicode")
            except IOError as e:
                self.log.error("[on_buttonSetLicense_clicked]: Error reading support subscription file: %s" % e.getDescription)
                self.popupError(e.getDescription() + "\n\n" + _("Error reading support subscription file."))
            try:
                licret = self.lotpclient.connect('/system/setSupport', {}, {'license':file_contents})
            except LinOTPClientError as e:
                self.log.error("[on_buttonSetLicense_clicked]: Error setting support license: %s" % e.getDescription)
                self.popupError(e.getDescription() + "\n\n" + _("Error setting up support license."))

            self.license_get()
            self.license_show()
        else:
            dialog.destroy()
        return licret

    def license_show(self):
        textbuffer = self.builder.get_object('textviewLicense').get_buffer()
        lic_string = ""
        licdict = self.lic.getlicenseDict()
        self.log.info("[license_show]: %r", licdict)
        for k, v in licdict.items():
                if v:
                    key = '{:<20}'.format("%s:" % k)
                    lic_string += "%s\t %s\n" % (key, v)
        textbuffer.set_text(lic_string)


##### Refresh

    def clear_progressbar(self):
        self.progressbarImport.set_fraction(0)
        self.progressbarImport.set_text("")

    def refresh(self, widget):
        self.readtoken()
        self.readuser()
        self.readaudit()
        self.clear_progressbar()

    def setStatusLine(self, text, label=1):
        if 2 == label:
            self.gui_statusLabel2.set_text(text)
        else:
            self.gui_statusLabel1.set_text(text)

        #self.do_pulse()


##### Policies

    def getPolicyDefinitions(self):
        rv = self.lotpclient.connect('/system/getPolicyDef', {})
        if True == rv['result']['status']:
            self.policyDef = rv['result']['value']
            #print self.policyDef
        else:
            self.popupError(_("Problem fetching the policy definitions!"))

    def fillComboboxScope(self):
        self.getPolicyDefinitions()
        #fill the "comboboxScope" here.
        scopestore = self.builder.get_object('scopestore')
        scopestore.clear()
        for scope in self.policyDef:
            #print scope
            scopestore.append([scope])
        self.builder.get_object('comboboxScope').set_model(scopestore)



    def on_comboboxScope_changed(self, widget):
        try:
            text1 = _("In the current scope the following actions are allowed:\n\n")
            aindex = self.builder.get_object('comboboxScope').get_active()
            current_scope = self.builder.get_object('scopestore')[aindex][0]
            text2 = ", ".join(sorted(self.policyDef[current_scope].keys()))
            self.builder.get_object('entryPolicyAction').set_tooltip_text(text1 + text2)
        except:
            print "on_combobxScope_changed not applicable"

    def listPolicy(self):
        '''
        This function lists the policies in the policy dialog in the
        treeviewpolicy
        '''
        policies = {}
        try:
            self.log.debug(">>>>> starting to read policies")
            rv = self.lotpclient.connect('/system/getPolicy', {"display_inactive" : 1})
            self.log.debug(">>>>> done reading policies")

            self.log.debug(">>>>> starting to read policies definitions")
            polDef = self.lotpclient.connect('/system/getPolicyDef', {})
            self.log.debug(">>>>> done reading policies definitions")

            self.fillComboboxScope()

            # check if ok
            if True == rv['result']['status']:
                policies = rv['result']['value']
                self.obj_pollist.clear()

                for k in policies:
                    self.log.debug(" >> inserting policy %s " % k)
                    self.obj_pollist.insert(0, (
                        1 if policies[k].get("active", "True") == "True" else 0,
                        k,
                        policies[k]['user'],
                        policies[k]['action'],
                        policies[k]['scope'],
                        policies[k]['realm'],
                        policies[k]['time'],
                        policies[k].get('client', "")))

                self.obj_pollist_sort = gtk.TreeModelSort(self.obj_pollist)
                self.gui_poltreeview.set_model(self.obj_pollist_sort)

            else:
                self.popupError("Could not retrieve the policies")

        except LinOTPClientError as e:
            # check if we cannot connect due to authentication
            if e.getId() in [1005, 1006]:
                self.loginLinOTPServer(self)
            else:
                self.popupError(e.getDescription() +
                    "\n\n" + _("Please setup the LinOTP Server in the Admin Client configuration correctly"))


    def on_policy_activate(self, widget):
        self.builder.get_object('dialogPolicy').show()
        self.listPolicy()

    def on_buttonPolicyClose_clicked(self, widget):
        self.builder.get_object('dialogPolicy').hide()

    def on_policydelete(self, widget):
        if self.question_dialog(_("Are you sure you want to delete the highlighted policy?")):
            selected_policy = self.gui_poltreeview.get_selection()
            policystore, selected_rows = selected_policy.get_selected_rows()
            if (len(selected_rows) == 0):
                self.popupError(_("No Policy selected"))
            else:
                for row in selected_rows:
                    self.log.debug(">> deleting policy in row %i" % row)
                    #self.setStatusLine( _("deleting policy"), True)
                    item = policystore.get_iter_first()
                    i = 0
                    while (item != None):
                        name = policystore.get_value(item, 1)
                        if i == row[0]:
                            self.log.debug(">> deleting policy with name %s" % name)
                            try:
                                rv = self.lotpclient.connect('/system/delPolicy', {'name': name})
                            except LinOTPClientError as e:
                                self.popupError(e.getDescription())
                        i += 1
                        item = policystore.iter_next(item)

        self.listPolicy()

    def on_policyedit(self, widget):
        selected_policy = self.gui_poltreeview.get_selection()
        policystore, selected_rows = selected_policy.get_selected_rows()
        for row in selected_rows:
            item = policystore.get_iter_first()
            i = 0
            while (item != None):
                if i == row[0]:
                    active = policystore.get_value(item, 0)
                    self.builder.get_object('checkbutton_policy_active').set_active(active == "1")
                    self.builder.get_object('entryPolicyName').set_text(policystore.get_value(item, 1) or "")
                    self.builder.get_object('entryPolicyUser').set_text(policystore.get_value(item, 2) or "")
                    self.builder.get_object('entryPolicyAction').set_text(policystore.get_value(item, 3) or "")
                    self.builder.get_object('entryPolicyRealm').set_text(policystore.get_value(item, 5) or "")
                    self.builder.get_object('entryPolicyTime').set_text(policystore.get_value(item, 6) or "")
                    self.builder.get_object('entryPolicyClient').set_text(policystore.get_value(item, 7) or "")
                    ##
                    scope = policystore.get_value(item, 4)
                    i = 0
                    aindex = -1
                    for row in self.builder.get_object('scopestore'):
                        if row[0] == scope:
                            aindex = i
                            break
                        i = i + 1
                    self.builder.get_object('comboboxScope').set_active(aindex)
                    break
                i += 1
                item = policystore.iter_next(item)

    def on_policyadd(self, widget):
        try:
            self.log.debug(">>>>> Adding Policy")
            aindex = self.builder.get_object('comboboxScope').get_active()

            rv = self.lotpclient.connect('/system/setPolicy', {
                    'active' : "True" if self.builder.get_object('checkbutton_policy_active').get_active() else "False",
                    'name' : self.builder.get_object('entryPolicyName').get_text(),
                    'user' : self.builder.get_object('entryPolicyUser').get_text(),
                    'action' : self.builder.get_object('entryPolicyAction').get_text(),
                    'scope' : self.builder.get_object('scopestore')[aindex][0],
                    'realm' : self.builder.get_object('entryPolicyRealm').get_text(),
                    'client' : self.builder.get_object('entryPolicyClient').get_text(),
                    'time' : self.builder.get_object('entryPolicyTime').get_text()
                })
            self.log.debug(">>>>> done reading policies")

            # check if ok
            if True == rv['result']['status']:
                self.listPolicy()

        except LinOTPClientError as e:
            # check if we cannot connect due to authentication
            if e.getId() in [1005, 1006]:
                self.loginLinOTPServer(self)
            else:
                self.popupError(e.getDescription())

    def on_dialog_close(self, widget, event=None):
        widget.hide()
        return True

    ##############################################################################
    ## Lost token

    def dialog_losttoken_open(self, widget):
        serials = self.get_selected_serials()
        if len(serials) != 1:
            self.popupError(_("You must exactly select one token to run the losttoken function."))
        else:
            text = _("The token %s was lost?\nYou may enroll a temporary token and\nautomatically disable the lost token.") % serials[0]
            self.data_cache['losttoken_serial'] = serials[0]
            self.builder.get_object('dialogLostToken').show()
            self.builder.get_object('labelLostToken').set_text(text)

    def dialog_losttoken_close(self, widget):
        self.builder.get_object('dialogLostToken').hide()

    def dialog_losttoken_go(self, widget):
        try:
            self.log.debug(">>>>> LostToken")

            rv = self.lotpclient.connect('/admin/losttoken', {
                    'serial' : self.data_cache.get("losttoken_serial", "") })

            # check if ok
            if True == rv['result']['status']:
                self.popupInfo(_("Token %s enrolled. Use the old PIN with the password %s.\nThe token is valid till %s") %
                               (rv['result']['value']['serial'],
                                rv['result']['value']['password'],
                                rv['result']['value']['end_date']))
            else:
                self.popupError(rv['result']['error']['message'])
            self.readtoken()
            self.builder.get_object('dialogLostToken').hide()

        except LinOTPClientError as e:
            # check if we cannot connect due to authentication
            if e.getId() in [1005, 1006]:
                self.loginLinOTPServer(self)
            else:
                self.popupError(e.getDescription())

    def clear_userfilter(self, widget):
        self.builder.get_object('entryFilterUser').set_text("")

    def clear_tokenfilter(self, widget):
        self.gui_entryFilter.set_text("")

# we start the app like this...
def setup_app(*args):
    main = LinOTPGui()

if __name__ == "__main__":
    #app = LinOTPGui()
    #app.run()

    splash = gtk.Window(gtk.WINDOW_TOPLEVEL)
    # [...] set splash up
    splash.set_position(gtk.WIN_POS_CENTER)
    splash.set_resizable(False)
    splash.set_decorated(False)
    splash.show()
    image = gtk.Image()
    transparent_color = None
    xpm_data = [
        "300 64 246 2",
        "  	c None",
        ". 	c #FFFFFF",
        "+ 	c #FFFAF7",
        "@ 	c #FFEEE1",
        "# 	c #FFFBF8",
        "$ 	c #FFF0E4",
        "% 	c #FEB980",
        "& 	c #FE943F",
        "* 	c #FE8727",
        "= 	c #FE8625",
        "- 	c #FE9540",
        "; 	c #FEBB85",
        "> 	c #FFEFE2",
        ", 	c #FFD0AB",
        "' 	c #FE8828",
        ") 	c #FE8728",
        "! 	c #FFD2AE",
        "~ 	c #FFFDFC",
        "{ 	c #FFE6D3",
        "] 	c #FFDEC4",
        "^ 	c #FFD6B5",
        "/ 	c #FFCFA8",
        "( 	c #FFC89C",
        "_ 	c #FFCDA4",
        ": 	c #FFD3B0",
        "< 	c #FFDABC",
        "[ 	c #FFE1C8",
        "} 	c #FFE6D1",
        "| 	c #FFF7F1",
        "1 	c #FFFDFB",
        "2 	c #FFFBF7",
        "3 	c #FFF8F4",
        "4 	c #FFF6EF",
        "5 	c #FFF4EB",
        "6 	c #FFF2E8",
        "7 	c #FFFDFA",
        "8 	c #FEA963",
        "9 	c #FFC393",
        "0 	c #FFDDC1",
        "a 	c #FE8626",
        "b 	c #FFE0C7",
        "c 	c #FFEDDE",
        "d 	c #FEBB84",
        "e 	c #FEA257",
        "f 	c #FE8B2E",
        "g 	c #FE9642",
        "h 	c #FEAC69",
        "i 	c #FEC291",
        "j 	c #FFDBBE",
        "k 	c #FE9F51",
        "l 	c #FFDABD",
        "m 	c #FEA55D",
        "n 	c #FE923B",
        "o 	c #FE9038",
        "p 	c #FE8F35",
        "q 	c #FE8D32",
        "r 	c #FE892B",
        "s 	c #FE9A49",
        "t 	c #FEA45C",
        "u 	c #FEAF6F",
        "v 	c #FEBA83",
        "w 	c #FFC597",
        "x 	c #FFD0AA",
        "y 	c #FFDCC0",
        "z 	c #FFF8F2",
        "A 	c #FE9C4D",
        "B 	c #FEB070",
        "C 	c #FEB173",
        "D 	c #FFF4EC",
        "E 	c #FFC99E",
        "F 	c #FE9D4E",
        "G 	c #FEB478",
        "H 	c #FFDDC2",
        "I 	c #FFFCFA",
        "J 	c #FE9139",
        "K 	c #FFD5B4",
        "L 	c #FE9946",
        "M 	c #FE8A2C",
        "N 	c #FEA761",
        "O 	c #FFF4EA",
        "P 	c #FEA760",
        "Q 	c #FFE1C9",
        "R 	c #FEAA66",
        "S 	c #FE933C",
        "T 	c #FFD3AF",
        "U 	c #FFFEFE",
        "V 	c #FEB57A",
        "W 	c #FFECDC",
        "X 	c #FFCAA0",
        "Y 	c #FFCDA5",
        "Z 	c #FFF1E5",
        "` 	c #FEAE6E",
        " .	c #FEA155",
        "..	c #FFE5D0",
        "+.	c #FFC392",
        "@.	c #FFFEFD",
        "#.	c #FFFEFC",
        "$.	c #FFFCF8",
        "%.	c #FE8A2D",
        "&.	c #FEC292",
        "*.	c #FEB67C",
        "=.	c #FE9744",
        "-.	c #FE9947",
        ";.	c #FE9B4B",
        ">.	c #FFE4CE",
        ",.	c #FFC799",
        "'.	c #FFD4B1",
        ").	c #FFE3CD",
        "!.	c #FFF1E6",
        "~.	c #FEB376",
        "{.	c #FFD7B6",
        "].	c #FFE8D6",
        "^.	c #FFF5EE",
        "/.	c #FFEAD9",
        "(.	c #FEB77E",
        "_.	c #FEA65F",
        ":.	c #FE943E",
        "<.	c #FFD9BB",
        "[.	c #FE8829",
        "}.	c #FEBE8B",
        "|.	c #FFF9F4",
        "1.	c #FFE2CB",
        "2.	c #FFECDE",
        "3.	c #FEAB67",
        "4.	c #FFE9D7",
        "5.	c #FEB071",
        "6.	c #FEC190",
        "7.	c #FFCEA6",
        "8.	c #FFFBF9",
        "9.	c #FE8E33",
        "0.	c #FFF3E9",
        "a.	c #FFE4CF",
        "b.	c #FE8C2F",
        "c.	c #FEC08E",
        "d.	c #FFDABB",
        "e.	c #FFC494",
        "f.	c #FEBF8C",
        "g.	c #FFEDDF",
        "h.	c #FFFCF9",
        "i.	c #FEAD6B",
        "j.	c #FE9F52",
        "k.	c #FEB579",
        "l.	c #FFD8B9",
        "m.	c #FFC89D",
        "n.	c #FEA359",
        "o.	c #FFF7EF",
        "p.	c #FFDCC1",
        "q.	c #FFD7B7",
        "r.	c #FEA156",
        "s.	c #FFD5B3",
        "t.	c #FE8F36",
        "u.	c #FFF0E3",
        "v.	c #FE9845",
        "w.	c #FEC08D",
        "x.	c #FE892A",
        "y.	c #FFF7F0",
        "z.	c #FE8E34",
        "A.	c #FEBE8A",
        "B.	c #FEB275",
        "C.	c #FFF2E7",
        "D.	c #FEA053",
        "E.	c #FFE2CA",
        "F.	c #FFF8F3",
        "G.	c #FEA65E",
        "H.	c #FFCCA4",
        "I.	c #FFC79B",
        "J.	c #FFEEE0",
        "K.	c #FEA054",
        "L.	c #FFE7D3",
        "M.	c #FEBE89",
        "N.	c #FE9E51",
        "O.	c #FEAB69",
        "P.	c #FCEFEF",
        "Q.	c #FEB67B",
        "R.	c #FE8C30",
        "S.	c #FFFFFE",
        "T.	c #FE913A",
        "U.	c #FE9641",
        "V.	c #FB7C22",
        "W.	c #F05A19",
        "X.	c #E63E1A",
        "Y.	c #DB2726",
        "Z.	c #D40000",
        "`.	c #FFDFC6",
        " +	c #FFF5ED",
        ".+	c #FFEFE3",
        "++	c #FEC18F",
        "@+	c #FFC79A",
        "#+	c #FFCCA3",
        "$+	c #FC8023",
        "%+	c #ED5016",
        "&+	c #DD1B08",
        "*+	c #D40100",
        "=+	c #FEA45B",
        "-+	c #F76E1E",
        ";+	c #E5380F",
        ">+	c #D60702",
        ",+	c #DF240A",
        "'+	c #E3300D",
        ")+	c #EC5D32",
        "!+	c #ED8E89",
        "~+	c #E35A5A",
        "{+	c #D40101",
        "]+	c #E5360F",
        "^+	c #D40200",
        "/+	c #D50301",
        "(+	c #ED5B29",
        "_+	c #FFD6B4",
        ":+	c #FFC596",
        "<+	c #FEBD88",
        "[+	c #F7711F",
        "}+	c #DA1205",
        "|+	c #D50503",
        "1+	c #F49C80",
        "2+	c #FFFAF6",
        "3+	c #FFD2AF",
        "4+	c #F3631B",
        "5+	c #D70802",
        "6+	c #D40303",
        "7+	c #ED9696",
        "8+	c #FE9743",
        "9+	c #FFDFC5",
        "0+	c #FEBC86",
        "a+	c #FEB880",
        "b+	c #FFCA9F",
        "c+	c #F5A185",
        "d+	c #D50606",
        "e+	c #FE9C4C",
        "f+	c #FE9E50",
        "g+	c #D50505",
        "h+	c #FE933D",
        "i+	c #FFCBA2",
        "j+	c #FFD9BA",
        "k+	c #FFCEA7",
        "l+	c #FFE8D5",
        "m+	c #FFC698",
        "n+	c #FEBA82",
        "o+	c #FEAA65",
        "p+	c #FEA862",
        "q+	c #FFEBDB",
        "r+	c #FFCFA9",
        "s+	c #FFCBA1",
        "t+	c #FFF3EA",
        "u+	c #FFDEC3",
        "v+	c #FFD4B2",
        "w+	c #FFE1CA",
        "                                                                            . + @ # . .                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 ",
        "                                                                      . $ % & * = * - ; > .                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             ",
        ". . . . . . . . . . . . .                                           . , ' = = = = = = = ) ! .                                                                                                                                         . . ~ @ { ] ^ / ( _ : < [ } | . .                               . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .         . . . . . . . . . . 1 2 3 4 5 6 7 . . . .                                                                                                                                                                                 ",
        ". 8 - - - - - - - - - 9 .                                         . 0 a = = = = = = = = = * b .                                                                                                                                 . c : d e f = = = = = = = = = = = a g h i j +                         . k - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - l .       . m n o p q f r ) = = = = = = = a p s t u v w x y z .                                                                                                                                                                     ",
        ". A = = = = = = = = = d .                                         . B = = = = = = = = = = = C .                                                                                                                           . D E F = = = = = = = = = = = = = = = = = = = = = q G H I                   . J = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = K .       . L = = = = = = = = = = = = = = = = = = = = = = = M N E O .                                                                                                                                                               ",
        ". A = = = = = = = = = d .                                         . P = = = = = = = = = = = N .                                                                                                                       . Q R ' = = = = = = = = = = = = = = = = = = = = = = = = = = S T U               . J = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = K .       . L = = = = = = = = = = = = = = = = = = = = = = = = = = r V W .                                                                                                                                                           ",
        ". A = = = = = = = = = d .                                         . X = = = = = = = = = = = Y .                                                                                                                   . Z ` = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =  ...            . J = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = K .       . L = = = = = = = = = = = = = = = = = = = = = = = = = = = = * +.@.                                                                                                                                                        ",
        ". A = = = = = = = = = d .                                           1 h = = = = = = = = = u #.                                                                                                                  $.+.%.= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = a &..         . J = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = K .       . L = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = t 4                                                                                                                                                       ",
        ". A = = = = = = = = = d .                                             I ( n = = = = = & X 1                                                                                                                   z t = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = *.~       . J = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = K .       . L = = = = = = = = = q =.-.;.L q = = = = = = = = = = = = = = = = m 1                                                                                                                                                     ",
        ". A = = = = = = = = = d .                                               . $.>.T ,.'.).#                                                                                                                   . !.;.= = = = = = = = = = = = a  .~.w {.].^./.< E (._.:.= = = = = = = = = = = = = = h 1     . 0 <.<.<.<.<.<.<.<.<.<.<.<.<.[.= = = = = = = = = (.<.<.<.<.<.<.<.<.<.<.<.<.<.6 .       . L = = = = = = = = = }.. . . . . |.@ 1.; p = = = = = = = = = = = = d .                                                                                                                                                   ",
        ". A = = = = = = = = = d .                                                                                                                                                                               . 2.S = = = = = = = = = = = = 3.4..                     . ).5.[.= = = = = = = = = = = = 6..                               . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..                 8.'.9.= = = = = = = = = = [.0.                                                                                                                                                  ",
        ". A = = = = = = = = = d .                                                                                                                                                                               # ;.= = = = = = = = = = = N ...                             . 4.s = = = = = = = = = = = ' ]..                             . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..                   . a.b.= = = = = = = = = = c..                                                                                                                                                 ",
        ". A = = = = = = = = = d .                                           . . . . . . . . . . . . .               . . . . . . . . . . .             . D a.d./ e.f.7.H g.h..                                 . v = = = = = = = = = = ' ^ .                                     # i.= = = = = = = = = = = A 1                             . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..                     . ^ = = = = = = = = = = j..                                                                                                                                                 ",
        ". A = = = = = = = = = d .                                           . k.q q q q q q q q q f..             . l.q q q q q q q q q ..      . W m.n.* = = = = = = = = a S }.o..                         . p.= = = = = = = = = = ' q..                                         # r.= = = = = = = = = = = s..                           . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..                       |.) = = = = = = = = = t..                                                                                                                                                 ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = = $ . . u.h = = = = = = = = = = = = = = = 9.w 3                       . v.= = = = = = = = = = c..                                             O f = = = = = = = = = = 3..                           . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..                       . F = = = = = = = = = = h.                                                                                                                                                ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = a I ~ +.%.= = = = = = = = = = = = = = = = = = F I                   . Q = = = = = = = = = = v.h.                                              . w.= = = = = = = = = = x.y.                          . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..                       . ;.= = = = = = = = = z..                                                                                                                                                 ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = J #.u = = = = = = = = = = = = = = = = = = = = = A..                 . B.= = = = = = = = = = T .                                                 | r = = = = = = = = = = x .                         . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..                       C.= = = = = = = = = = D..                                                                                                                                                 ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = A 5.= = = = = = = = = = = = = = = = = = = = = = * E.                z %.= = = = = = = = = r F.                                                  . G.= = = = = = = = = = (..                         . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..                     . H.= = = = = = = = = = ; .                                                                                                                                                 ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = = = = = = = = = q G.f.,.V ;.= = = = = = = = = = = V .               0 = = = = = = = = = = R .                                                   . I.= = = = = = = = = = 3..                         . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..                   . < M = = = = = = = = = a J.                                                                                                                                                  ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = = = = = = = K.L.U .     . U x ) = = = = = = = = =  ..             . 7.= = = = = = = = = = M..                                                   . H = = = = = = = = = = N..                         . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..                 U x ' = = = = = = = = = = O.P.                                                                                                                                                  ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = = = = = %.( ~               . Q.= = = = = = = = = R.S.            . A.= = = = = = = = = = X .                                                     { = = = = = = = = = = T..                         . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..         . . $ e.U.= = = = = = = = = V.W.X.Y.Z.Z.Z.Z.Z.Z.                                                                                                                                        ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = = = = a `..                   ).= = = = = = = = = =  +            . u = = = = = = = = = = K .                                                     .+= = = = = = = = = = r .                         . r = = = = = = = = = 7..                                   . L = = = = = = = = = j.++@+#+i k.N s * = = = = = = = = $+%+&+*+Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.                                                                                                                                  ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = = = = v .                     0.= = = = = = = = = = O             . =+= = = = = = = = = = E .                                                     J.= = = = = = = = = = - .                         . r = = = = = = = = = 7..                                   . L = = = = = = = = = = = = = = = = = = = = = = = = -+;+>+Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.                                                                                                                                ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = = = L 2                       # = = = = = = = = = = O             . i.= = = = = = = = = = *..                                                   . E.= = = = = = = = = = =+.                         . r = = = = = = = = = 7..                                   . L = = = = = = = = = = = = = = = = = = = = = = -+,+Z.Z.Z.'+)+!+~+{+Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.                                                                                                                              ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = = = m..                       # = = = = = = = = = = O             . % = = = = = = = = = = =+.                                                   . K = = = = = = = = = = B..                         . r = = = = = = = = = 7..                                   . L = = = = = = = = = = = = = = = = = = = = V.]+^+Z.Z./+(+_+U             Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.                                                                                                                            ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = = = E.                        # = = = = = = = = = = O             . :+= = = = = = = = = = J .                                                   . <+= = = = = = = = = = 6..                         . r = = = = = = = = = 7..                                   . L = = = = = = = = = = = = = = = = = = = [+}+Z.Z.Z.|+1+8.                  Z.Z.Z.Z.Z.Z.Z.Z.Z.                                                                                                                            ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = = ) 2+                        # = = = = = = = = = = O             . 3+= = = = = = = = = = = |                                                   @.S = = = = = = = = = = >.                          . r = = = = = = = = = 7..                                   . L = = = = = = = = = = = = = = = = = = 4+5+Z.Z.Z.6+7+                        Z.Z.Z.Z.Z.Z.Z.Z.                                                                                                                            ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = = 8+.                         # = = = = = = = = = = O               0.a = = = = = = = = = = s..                                               . 9+= = = = = = = = = = s .                           . r = = = = = = = = = 7..                                   . L = = = = = = = = = K.0+a+V *.<+9 b+c+d+Z.Z.Z.Z.                              Z.Z.Z.Z.Z.Z.Z.                                                                                                                            ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = = L .                         # = = = = = = = = = = O               . N.= = = = = = = = = = e+.                                               1 f+= = = = = = = = = = E .                           . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..             g+Z.Z.Z.Z.Z.                              Z.Z.Z.Z.Z.Z.Z.                                                                                                                            ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = = L .                         # = = = = = = = = = = O               . 9 = = = = = = = = = = = T .                                           . ,.= = = = = = = = = = r  +                            . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..           Z.Z.Z.Z.Z.Z.                                Z.Z.Z.Z.Z.Z.Z.                                                                                                                            ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = = L .                         # = = = = = = = = = = O                 g.[.= = = = = = = = = = f ].                                        . ^ [.= = = = = = = = = = m..                             . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..         Z.Z.Z.Z.Z.Z.                                  Z.Z.Z.Z.Z.Z.Z.                                                                                                                            ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = = L .                         # = = = = = = = = = = O                 . 0+= = = = = = = = = = = h+{ .                                   . 7.* = = = = = = = = = = m S.                              . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..         Z.Z.Z.Z.Z.Z.                                  Z.Z.Z.Z.Z.Z.Z.                                                                                                                            ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = = L .                         # = = = = = = = = = = O                   F.J = = = = = = = = = = = x.i+#..                           U j+f+= = = = = = = = = = = z.6                                 . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..       Z.Z.Z.Z.Z.Z.Z.                                  Z.Z.Z.Z.Z.Z.Z.                                                                                                                            ",
        ". A = = = = = = = = = d .                                           . u = = = = = = = = = d .             . K = = = = = = = = = L .                         # = = = = = = = = = = O                   . K = = = = = = = = = = = = = g k+2 .                 . @.{.e+= = = = = = = = = = = = R.b .                                 . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..       Z.Z.Z.Z.Z.Z.                                    Z.Z.Z.Z.Z.Z.Z.                                                                                          Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.  ",
        ". A = = = = = = = = = F d d d d d d d d d d d d d d d d d .         . u = = = = = = = = = d .             . K = = = = = = = = = L .                         # = = = = = = = = = = O                     . b+= = = = = = = = = = = = = = x.e }.! j >.].<.I.*.m T.= = = = = = = = = = = = = T.l+.                                   . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..     Z.Z.Z.Z.Z.Z.Z.                                    Z.Z.Z.Z.Z.Z.                                                                            Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.    ",
        ". A = = = = = = = = = = = = = = = = = = = = = = = = = = = .         . u = = = = = = = = = d .             . K = = = = = = = = = L .                         # = = = = = = = = = = O                       . m+= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = v.$                                       . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..     Z.Z.Z.Z.Z.Z.                                    Z.Z.Z.Z.Z.Z.Z.                                                                Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.        ",
        ". A = = = = = = = = = = = = = = = = = = = = = = = = = = = .         . u = = = = = = = = = d .             . K = = = = = = = = = L .                         # = = = = = = = = = = O                         . Y b.= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = ) n+|                                         . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..     Z.Z.Z.Z.Z.Z.                                    Z.Z.Z.Z.Z.Z.                                                          Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.                          Z.Z.Z.            ",
        ". A = = = = = = = = = = = = = = = = = = = = = = = = = = = .         . u = = = = = = = = = d .             . K = = = = = = = = = L .                         # = = = = = = = = = = O                           . Z o+= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = t /..                                           . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..   Z.Z.Z.Z.Z.Z.Z.                                    Z.Z.Z.Z.Z.Z.                                                  Z.Z.Z.Z.Z.Z.Z.Z.Z.                                                            ",
        ". A = = = = = = = = = = = = = = = = = = = = = = = = = = = .         . u = = = = = = = = = d .             . K = = = = = = = = = L .                         # = = = = = = = = = = O                               . {.D.= = = = = = = = = = = = = = = = = = = = = = = = = = * p+j+.                                               . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..   Z.Z.Z.Z.                                        Z.Z.Z.Z.Z.Z.                                              Z.Z.Z.Z.Z.Z.Z.                                                                      ",
        ". A = = = = = = = = = = = = = = = = = = = = = = = = = = = .         . u = = = = = = = = = d .             . K = = = = = = = = = L .                         # = = = = = = = = = = O                                   . q+<+J = = = = = = = = = = = = = = = = = = = = = s @+6 .                                                   . r = = = = = = = = = 7..                                   . L = = = = = = = = = }..   Z.                                              Z.Z.Z.Z.Z.Z.                                      Z.Z.Z.Z.Z.Z.                                                                                ",
        ". u A A A A A A A A A A A A A A A A A A A A A A A A A A A .         . }.A A A A A A A A A I..             . H A A A A A A A A A h .                         I A A A A A A A A A A 4                                         I L.r+(.K.%.= = = = = = = = = = = b.=+<+^ > .                                                         . D.A A A A A A A A A q..                                   . h A A A A A A A A A s+.                                                 Z.Z.Z.Z.Z.Z.                                  Z.Z.Z.Z.Z.                                                                                        ",
        ". . . . . . . . . . . . . . . . . . . . . . . . . . . . . .         . . . . . . . . . . . .                 . . . . . . . . . . . .                         . . . . . . . . . . . .                                                 . ~ t+2...u+{.x v+p.w+l+> #..                                                                 . . . . . . . . . . . .                                     . . . . . . . . . . . .                                                 Z.Z.Z.Z.Z.Z.                              Z.Z.Z.Z.                                                                                                ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                                                                      Z.Z.Z.Z.Z.                          Z.Z.Z.Z.                                                                                                      ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                                                                    Z.Z.Z.Z.Z.                      Z.Z.Z.Z.                                                                                                            ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                                                                  Z.Z.Z.Z.Z.                    Z.Z.Z.                                                                                                                  ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                                                                Z.Z.Z.Z.Z.                Z.Z.Z.                                                                                                                        ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                                                              Z.Z.Z.Z.Z.            Z.Z.Z.Z.                                                                                                                            ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                                                            Z.Z.Z.Z.Z.          Z.Z.Z.                                                                                                                                  ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                                                          Z.Z.Z.Z.Z.        Z.Z.Z.                                                                                                                                      ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                                                        Z.Z.Z.Z.Z.    Z.Z.Z.Z.                                                                                                                                          ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                                                    Z.Z.Z.Z.Z.    Z.Z.Z.Z.                                                                                                                                              ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                                                  Z.Z.Z.Z.Z.  Z.Z.Z.Z.                                                                                                                                                  ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                                                Z.Z.Z.Z.Z.Z.Z.Z.Z.                                                                                                                                                      ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                                            Z.Z.Z.Z.Z.Z.Z.Z.Z.Z.                                                                                                                                                        ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                                          Z.Z.Z.Z.Z.Z.Z.Z.Z.                                                                                                                                                            ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                                        Z.Z.Z.Z.Z.Z.Z.Z.                                                                                                                                                                ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                                    Z.Z.Z.Z.Z.Z.Z.Z.                                                                                                                                                                    ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                                  Z.Z.Z.Z.Z.Z.Z.                                                                                                                                                                        ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                                Z.Z.Z.Z.Z.Z.                                                                                                                                                                            ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                            Z.Z.Z.Z.Z.Z.                                                                                                                                                                                ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                        Z.Z.Z.Z.Z.Z.                                                                                                                                                                                    ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                      Z.Z.Z.Z.Z.                                                                                                                                                                                        ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                  Z.Z.Z.Z.Z.                                                                                                                                                                                            ",
        "                                                                                                                                                                                                                                                                                                                                                                                                                  Z.Z.Z.                                                                                                                                                                                                "
    ]
    pixmap, mask = gtk.gdk.pixmap_create_from_xpm_d(splash.window, transparent_color, xpm_data)
    image.set_from_pixmap(pixmap, mask)
    image.show()
    vbox = gtk.VBox()
    splash.add(vbox)
    button = gtk.Button()
    button.add(image)
    vbox.add(button)
    button.show()
    splash.set_keep_above(True)
    welcome = gtk.Label()
    welcome.set_text(_("loading and trying to connect to server..."))
    vbox.add(welcome)
    vbox.show()
    button.show()
    welcome.show()

    gobject.idle_add(setup_app)
    gtk.main()




