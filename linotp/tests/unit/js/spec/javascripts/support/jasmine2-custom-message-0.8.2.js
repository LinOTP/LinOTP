/*
 * jasmine2-custom-message
 * https://github.com/avrelian/jasmine2-custom-message
 *
 * Copyright (c) 2014 Sergey Radchenko
 * Licensed under the MIT license.
 */

'use strict';

(function() {
  var global = Function('return this')();
  if (! (global.jasmine && global.expect)) {
    return;
  }

  var isBrowserEnv = global.window && global === global.window;
  var isCommonJS = typeof module !== 'undefined' && typeof module.exports === 'object';


  var ofType = function(val) {
    var types = [].slice.call(arguments, 1);
    var valType = val === null ? 'null' : typeof val;
    return types.indexOf(valType) > -1;
  };

  var formatString = function(data, message) {
    message = message.replace(/#\{actual\}/g, data.actual);
    message = message.replace(/#\{expected\}/g, data.expected);
    return message;
  };

  var getMessage = function(data, message) {

    while (! ofType(message, 'string', 'number', 'boolean')) {
      switch (true) {
        case ofType(message, 'undefined', 'null'):
          message = data.message || 'You cannot use `' + message + '` as a custom message';
          break;
        case ofType(message, 'function'):
          message = message.call(data);
          break;
        case message && ofType(message.toString, 'function') && message.toString().indexOf('[object ') !== 0:
          message = message.toString();
          break;
        case JSON && ofType(JSON.stringify, 'function'):
          message = JSON.stringify(message);
          break;
        default:
          message = 'N/A';
      }
    }

    if (ofType(message, 'string')) {
      return formatString(data, message);
    }

    return message.toString();
  };

  var wrapAddExpectationResult = function(addExpectationResult, customMessage) {
    return function(passed, data) {
      data.message = getMessage(data, customMessage);
      addExpectationResult(passed, data);
    };
  };

  var wrapExpect = function(expect, customMessage) {
    return function(actual) {
      var assertion = expect(actual);
      assertion.addExpectationResult = assertion.not.addExpectationResult = wrapAddExpectationResult(assertion.addExpectationResult, customMessage);
      return assertion;
    };
  };

  var defineSince = function() {
    global.since = function(customMessage) {
      return {
        expect: wrapExpect(global.expect, customMessage)
      };
    };
  };

  if (isBrowserEnv) {
    defineSince();
  } else {
    if (isCommonJS) {
      module.exports = defineSince();
    }
  }
})();