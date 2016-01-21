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
Provide useful functions to process json objects.
The most useful are:
    getJson:         which will navigate through json dictionary.
    checkJsonValues: which will validate json data against a predefined value.
"""

import json
import re

import pkg_resources
from distutils.version import LooseVersion

# RegexType is only a reference to Regular-Expression
# runtime type. In order to identify a Regular-Expression 
# object, you may use:
#     isinstance(yourobject, RegexType)
# ... which will return True if yourobject is a 
# regular-expression object. 
RegexType = type(re.compile(''))

class JsonUtils:
    # Extract the Json object from the webapi response. 
    @staticmethod
    def getBody(response):
        """
        Parses the response body as JSON and returns it. WebOb added the property
        json_body (alias json) in version 1.2

        :param response: A WebOb response object
        """
        current_webob = LooseVersion(pkg_resources.get_distribution('webob').version)
        if current_webob >= LooseVersion('1.2'):
            return response.json_body
        else:
            return json.loads(response.body, encoding=response.charset)
    
    # The getJson function implements navigation through json-object dictionaries.  
    # If the path argument is string, then the path is split over "/" character.
    # Else, for each element in path, the program will go deeper and deeper (each 
    # intermediate object must be a non-empty dictionary). 
    @staticmethod
    def getJson(object, path, defaultValue = None):
        if object is None:
            return defaultValue
        
        if isinstance(path, basestring):
            path = path.split('/')
        else:
            try:
                # Check if path is iterable...
                path = iter(path)
            except TypeError:
                path = [path] 
        
        temp = object
        for key in path:
            temp = temp.get(key, None)
            if temp is None:
                return defaultValue
        return temp

    # This function is used in object comparison. 
    # If check should succeed if values are different string-types but contain the same value.
    # Also. for array, each different element must be equal.      
    @staticmethod
    def compareValue(value1, value2):
        if isinstance(value1, basestring):
            if isinstance(value2, basestring):
                if value1 == value2:
                    return True
        elif type(value1) == type(value2):
            if value1 == value2:
                return True
            if isinstance(value1, list):
                if len(value1) <> len(value2):
                    return False
                for i in range(len(value1)):
                    if not JsonUtils.compareValue(value1[i], value2[i]):
                        return False
                return True
        return False
    
    # This function is used in dictionary comparison. 
    # The test will not check if dictionaries are 100% equal, but only if 
    # the name-values from "dictionary" (second argument) are present 100% into  
    # the "testDictionary" (first parameter, test for inclusion). 
    @staticmethod
    def checkDictionary(testDictionary, dictionary):
        for key in testDictionary.keys():
            value1 = testDictionary.get(key, None)
            if value1 is None:
                # Check Value; value must exist in dictionary
                # (because of that, default is not None)!
                if not dictionary.get(key, True) is None:
                    return False
            else:
                value2 = dictionary.get(key, None)
                if not JsonUtils.compareValue(value1, value2):
                    return False
        return True

    # Check json object values.
    # If expectedValue (value) is dictionary, we test only inclusion.
    # If some value-object is actually a regular expression, the program will  
    # try to match the name/value against the pattern, and if the pattern will 
    # match, then the check is considered successful. 
    # Supplementary, if the regular expression contains name-captures, the 
    # captured groups must also be available info the namedValues (else, the 
    # test will fail). 
    @staticmethod
    def checkJsonValues(object, value, namedValues = {}):
        if isinstance(value, dict):
            for key in value.keys():
                if isinstance(key, RegexType):
                    temp = None
                    for key2 in object.keys():
                        # Find a key that match the Regex pattern!
                        match = key.match(key2)
                        if not match is None:
                            # For named-capture we compare values 
                            # with the values available in params! 
                            if not JsonUtils.checkDictionary(match.groupdict(None), namedValues): 
                                break
                            temp = object.get(key2, None)
                            break
                else:
                    temp = object.get(key, None)
                
                # If temp is not None, then a match in json dictionary was found!
                if temp is None or \
                   not JsonUtils.checkJsonValues(temp, value[key], namedValues):
                    return False
            return True
        elif type(value) == RegexType:
            # The compare is performed with a Regex object! 
            match = value.match(object)
            if match is None or \
               not JsonUtils.checkDictionary(match.groupdict(None), namedValues):
                return False
            return True
        elif JsonUtils.compareValue(value, object):
            return True
        return False
