'use strict';

describe("callback for ldap resolver test button", function() {

  var errorMessage = "this is the error message";

  var ldapErrorResponse = JSON.stringify({
    "version": "LinOTP 2.9.3.dev0",
    "jsonrpc": "2.0802",
    "result": {
      "status": true,
      "value": {
         "result": "error",
         "desc": "{'desc': \"" + errorMessage + "\"}"
      }
    },
    "id": 1
  });

  var linotpErrorResponse = JSON.stringify({
    "version": "LinOTP 2.9.3.dev0",
    "jsonrpc": "2.0802",
    "result": {
      "status": false,
      "error": {
         "message": errorMessage,
         "code": -311
      }
    },
    "id": 1
  });

  var successResponse = JSON.stringify({
   "version": "LinOTP 2.9.3.dev0",
   "jsonrpc": "2.0802",
   "result": {
      "status": true,
      "value": {
         "result": "success",
         "desc": [
            {"userid": "cn=XY,ou=people,dc=blackdog,dc=corp,dc=example,dc=com"},
            {"userid": "cn=Z,ou=people,dc=blackdog,dc=corp,dc=example,dc=com"}
         ]
      }
   },
   "id": 1
});

  var successResponseLDAPLimit = JSON.stringify({
   "version": "LinOTP 2.9.3.dev0",
   "jsonrpc": "2.0802",
   "result": {
      "status": true,
      "value": {
         "result": "success SIZELIMIT_EXCEEDED",
         "desc": [
            {"userid": "cn=XY,ou=people,dc=blackdog,dc=corp,dc=example,dc=com"},
            {"userid": "cn=Z,ou=people,dc=blackdog,dc=corp,dc=example,dc=com"}
         ]
      }
   },
   "id": 1
  });

  var expectedResultFailed = "Connection test failed";
  var expectedResultSuccess = "Connection test successful";

  beforeEach(function() {
    window.i18n = jasmine.createSpyObj('i18n', ['gettext']);
    window.i18n.gettext.and.callFake(function(text) {
      return text;
    });

    window.alert_box = jasmine.createSpy();

    window.sprintf = jasmine.createSpy().and.callFake(function(text, value) {
      return text;
    });

  })

  function checkProgressIndicatorClosed(fn){
    var hideSpy = spyOn($.fn, 'hide');

    // make the call to the function under test
    fn();

    expect(hideSpy).toHaveBeenCalled();

    // expect that any call to $.fn.hide() used the
    // '#progress_test_ldap' selector in order to close
    // the ldap test progress bar
    since("Expected $.fn.hide() to have been called on #progress_test_ldap selector").
    expect(hideSpy.calls.all()).toContain(
      jasmine.objectContaining({
        object: $('#progress_test_ldap')
      })
    );
  }

  function check_alert_box_calls(resultMatcher, messageMatcher) {
    since("Expect alert box to have been called exactly once").
    expect(window.alert_box.calls.count()).toEqual(1);

    var args = window.alert_box.calls.argsFor(0);

    since("Expect alert box to display the test result \""+resultMatcher.source+"\"").
    expect(args[0].text).toMatch(resultMatcher);

    since("Expect alert box to display the message \""+ messageMatcher.source+"\"").
    expect(args[0].text).toMatch(messageMatcher);
  }

  it('closes the test result progress indicator', function() {
    checkProgressIndicatorClosed(function() {
      processLDAPTestResponse({responseText: successResponse}, "success");
    });
  })

  it('closes the test result progress indicator on http error', function() {
    checkProgressIndicatorClosed(function() {
      processLDAPTestResponse({responseText: ""}, "error");
    });
  })

  it('displays the error message on linotp error result', function() {
    processLDAPTestResponse({responseText: linotpErrorResponse}, "success");

    check_alert_box_calls(
      new RegExp(expectedResultFailed),
      new RegExp(errorMessage)
    );
  });

  it('displays the error message on ldap error result', function() {
    processLDAPTestResponse({responseText: ldapErrorResponse}, "success");

    check_alert_box_calls(
      new RegExp(expectedResultFailed),
      new RegExp(errorMessage)
    );
  });

  it('displays an error message dialog on http error', function() {
    processLDAPTestResponse({responseText: ""}, "error");

    check_alert_box_calls(
      new RegExp(expectedResultFailed),
      new RegExp("Connection to LinOTP failed", "i")
    );
  });

  it('shows correct user count and success message', function() {

    processLDAPTestResponse({responseText: successResponse}, "success");

    var message = /number of users found/i;

    // sprintf should be called once to insert users found into message
    expect(window.sprintf.calls.count()).toBe(1);
    expect(window.sprintf.calls.argsFor(0)[0]).toMatch(message);
    expect(window.sprintf.calls.argsFor(0)[1]).toBe(2);

    check_alert_box_calls(
      new RegExp(expectedResultSuccess),
      message
    );
  });

  it('shows size limit exceeded message', function() {

    processLDAPTestResponse({responseText: successResponseLDAPLimit}, "success");

    var message = /size limit/i;

    check_alert_box_calls(
      new RegExp(expectedResultSuccess),
      new RegExp(message)
    );
  });
});