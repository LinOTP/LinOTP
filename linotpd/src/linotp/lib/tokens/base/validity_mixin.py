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

from datetime import datetime


class TokenValidityMixin(object):
    """
    A mixin for the Token validity handling which could be

    * time based with
    ** start and end validity period

    * counter based with
    ** access counter based
    ** success counter based

    Stored values are

    for the success counters:

        count_auth_success_max
        count_auth_success

    for the access counters:

        count_auth_max
        count_auth

    for the time period:

        validity_period_start
        validity_period_end

    TODO: currently the validity info is stored in the token info
          but in a redesign could be moved into a dedicated table or column

    """

    # ---------------------------------------------------------------------- --

    # success counter handling

    @property
    def count_auth_success_max(self):
        ''' get the counter for the maximum allowed successful logins '''

        return int(self.getFromTokenInfo("count_auth_success_max", 0) or 0)

    @count_auth_success_max.setter
    def count_auth_success_max(self, count):
        ''' Sets the counter for the maximum allowed successful logins '''

        self.addToTokenInfo("count_auth_success_max", int(count))

    @property
    def count_auth_success(self):
        ''' getter for the count_auth_success '''

        return int(self.getFromTokenInfo("count_auth_success", 0) or 0)

    @count_auth_success.setter
    def count_auth_success(self, count):
        ''' setter for the count_auth_success '''

        self.addToTokenInfo("count_auth_success", int(count))

    def inc_count_auth_success(self):
        """
        increment the auth success counter
        """
        self.count_auth_success = self.count_auth_success + 1

        return self.count_auth_success

    # access counter handling

    @property
    def count_auth_max(self):
        return int(self.getFromTokenInfo("count_auth_max", 0) or 0)

    @count_auth_max.setter
    def count_auth_max(self, count):
        ''' Sets the counter for the maximum allowed login attemps '''
        self.addToTokenInfo("count_auth_max", int(count))

    @property
    def count_auth(self):
        return int(self.getFromTokenInfo("count_auth", 0))

    @count_auth.setter
    def count_auth(self, count):
        ''' Sets the counter for the occurred login attepms '''
        self.addToTokenInfo("count_auth", int(count))

    def inc_count_auth(self):
        ''' increment the access counter '''

        self.count_auth = self.count_auth + 1

        return self.count_auth

    # time based validity handling

    @property
    def validity_period_end(self):
        '''
        returns the end of validity period (if set)
        '''
        end_time = self.getFromTokenInfo("validity_period_end", '') or ''
        if end_time:
            return datetime.strptime(end_time, "%d/%m/%y %H:%M")
        return ''

    @validity_period_end.setter
    def validity_period_end(self, end_date):
        '''
        sets the end date of the validity period for a token
        '''
        # upper layer will catch. we just try to verify the date format
        datetime.strptime(end_date, "%d/%m/%y %H:%M")
        self.addToTokenInfo("validity_period_end", end_date)

    @property
    def validity_period_start(self):
        '''
        returns the start of validity period (if set)
        '''
        start_time = self.getFromTokenInfo("validity_period_start", '') or ''
        if start_time:
            return datetime.strptime(start_time, "%d/%m/%y %H:%M")
        return ''

    @validity_period_start.setter
    def validity_period_start(self, start_date):
        '''
        sets the start date of the validity period for a token
        '''
        #  upper layer will catch. we just try to verify the date format
        datetime.strptime(start_date, "%d/%m/%y %H:%M")
        self.addToTokenInfo("validity_period_start", start_date)

