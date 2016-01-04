#!/usr/bin/env python
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


'''
Run Radiusserver on some ports (default: 18012 and 18013) and authenticate
successfully with user "tester"

Test it with:
    echo "User-Name = tester@LOCAL, User-Password = secretpwd" | \
        radclient -s -x 127.0.0.1:18012 auth testing123
or:
    echo "User-Name = user_with_pin, User-Password = test123456" | \
        radclient -s -x 127.0.0.1:18012 auth testing123
etc.
'''

from pyrad.server import Server as RadiusServer
from pyrad.server import ServerPacketError, RemoteHost
from pyrad.dictionary import Dictionary

import pyrad.packet as packet
from pyrad.packet import AccessAccept, AccessReject, AccessChallenge

import socket
import sys
import os.path
import os

from getopt import getopt, GetoptError


myIP = socket.gethostbyname(socket.gethostname())

state_id = "11321312313213132"
users = { 'user_with_pin' : 'test123456',
          'user_no_pin'   : '654321',
          }

def checkUser(username, password, state):
    """
    check
    - if user and password is in our userbase
    - or with a given state, the password is one of
      the users passwords

      :return: True or False for auth request
               or None, to start a challenge
    """
    auth = None
    if username in users:
        auth = False
        if users[username] == password:
            auth = True

    ## handle a state request
    if state is not None and state == state_id:
        if password in users.values():
            auth = True
        else:
            auth = False

    return auth

class myRadiusServer(RadiusServer):

    def HandleAuthPacket(self, pkt):
        """Authentication packet handler.
        This is an empty function that is called when a valid
        authentication packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        :param pkt: packet to process
        :type  pkt: Packet class instance
        """

        # contents of User-Name
        username = pkt[1][0]
        # encrypted User-Password
        password = pkt.PwDecrypt(pkt[2][0])

        state = None
        try:
            state = pkt["State"][0]
        except Exception as exx:
            state = None

        #print password
        auth = checkUser(username, password, state)

        #print "Handling Auth Packet"
        reply = self.CreateReplyPacket(pkt)
        if auth is True:
            rcode = AccessAccept
        elif auth is False:
            rcode = AccessReject
        else:
            rcode = AccessChallenge
            try:
                reply['State'] = state_id
                reply['Reply-Message'] = "Enter your challenge reply:"
            except Exception as exx:
                print("Failed to add attribute State or Message")
                print("Did you specify a radius dictionary file?")
                raise exx

        reply.code = rcode

        #print self._fdmap
        #print self._realauthfds
        # FIXME: Is this always correct?
        # see: http://pastebin.com/v1X2jdTV
        self.SendReplyPacket(self._fdmap[self._realauthfds[0]], reply)


def usage(prog):
    """
    Print usage information and exit
    """
    print """
Usage:
        %s [--dict=###] [--authport=###] [--acctport=###] [--help]

        --dict=, -d         The path to a dictionary file (default is /etc/linotp2/dictionary)
        --authport=, -t     Port used for RADIUS authentication packets (default is 18012)
        --acctport=, -c     Port used for RADIUS accounting packets (default is 18013)
        --help, -h          Show this message and exit
""" % prog


def main():
    """
    main worker:
    * gather the input
    """
    param = {}
    user = "tester"
    password = "password"

    client1 = RemoteHost(myIP, "testing123", "lselap")
    client2 = RemoteHost("127.0.0.1", "testing123", "localhost")

    # Set default values (overwritten by command-line args)
    r_dict = "/etc/linotp2/dictionary"
    authport = 18012
    acctport = 18013

    prog = sys.argv[0]

    try:
        opts, args = getopt(
            sys.argv[1:],
            "d:t:c:h",
            [
                "dict=",
                "authport=",
                "acctport=",
                "help",
                ],
            )

    except GetoptError:
        print "There is an error in your parameter syntax:"
        usage(prog)
        sys.exit(1)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage(prog)
            sys.exit(0)
        elif opt in ('-d', '--dict'):
            if os.path.isfile(arg):
                r_dict = arg
            else:
                print("radius dictionary file  <%r> not found!" % arg)
        elif opt in ('-t', '--authport'):
            authport = int(arg)
        elif opt in ('-c', '--acctport'):
            acctport = int(arg)
        else:
            print "Unknown option %s" % opt

    params = {
                "addresses":["127.0.0.1", myIP],
                "authport": authport,
                "acctport": acctport,
                "hosts":{myIP:client1, "127.0.0.1":client2},
                }

    if os.path.isfile(r_dict) == False:
        ## falback: try the relative one
        r_dict = "config/dictionary"

    if os.path.isfile(r_dict):
        params["dict"] = Dictionary(r_dict)

    print "[ starting dummy radius server ]"
    serv = myRadiusServer(**params)


    return serv.Run()

if __name__ == '__main__':
    ## jump to the main worker
    main()
