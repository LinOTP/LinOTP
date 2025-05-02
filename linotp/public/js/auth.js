/*!
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010-2019 KeyIdentity GmbH
 *   Copyright (C) 2019-     netgo software GmbH
 *
 *   This file is part of LinOTP server.
 *
 *   This program is free software: you can redistribute it and/or
 *   modify it under the terms of the GNU Affero General Public
 *   License, version 3, as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the
 *              GNU Affero General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *    E-mail: info@linotp.de
 *    Contact: www.linotp.org
 *    Support: www.linotp.de
 *
 */

function clientUrlFetchSync(myUrl, params) {
  /*
   * clientUrlFetchSync - to submit a syncronous  http request
   *
   * @remark: introduced the params (:dict:) so we could switch to
   *          a POST request, which will allow more and secure data
   */

  var resp = $.ajax({
    url: myUrl,
    data: params,
    async: false,
    type: "POST",
  }).responseText;

  return resp;
}

function getOcra2Challenge() {
  var user = $("#user").val();
  var realm = $("#realm").val();
  var targetId = "display";
  var userId = "user2";

  var params = {};
  params["user"] = user;
  if (realm != undefined) {
    params["realm"] = realm;
  }
  params["pass"] = $("#pin").val();
  params["data"] = $("#challenge").val();
  params["qr"] = "img";

  var url = "/validate/check";

  try {
    var data = clientUrlFetchSync(url, params);
    if (typeof data == "object") {
      var err = data.result.error.message;
      alert(err);
    } else {
      var img = data;
      $("#" + targetId).html(img);
      $("#" + userId).val(user);
    }
  } catch (e) {
    alert(e);
  }
}

function triggerChallenge() {
  var user = $("#user").val();
  var realm = $("#realm").val();
  var pin = $("#pin").val();
  var data = $("#challenge").val();

  var $target = $("#display");
  var $transidInput = $("#transactionid");
  var $otpInput = $("#otp");

  var params = {};
  params["user"] = user;
  if (realm != undefined) {
    params["realm"] = realm;
  }
  params["pass"] = pin;
  params["data"] = data;
  params["qr"] = "html";
  params["content_type"] = 0;

  var url = "/validate/check";

  try {
    var data = clientUrlFetchSync(url, params);

    try {
      var json = typeof data == "object" ? data : JSON.parse(data);

      var message;

      if (json.result && !json.result.detail) {
        message = "Failed to trigger challenge";
        if (json.result.error && json.result.error.message) {
          message += "\n" + json.result.error.message;
        }
      } else {
        message = "response format unexpected";
      }

      alert(message);
      return;
    } catch (e) {}

    var htmlResponse = $(data);

    var img = htmlResponse.find("#challenge_qrcode");
    var lseqrurl = img.attr("alt");
    var transactionid = htmlResponse
      .find("#challenge_data .transactionid")
      .text();

    $target.html(img);
    $target.append("<p>" + decodeURIComponent(lseqrurl) + "</p>");
    $transidInput.val(transactionid);

    $otpInput.val("").focus();
  } catch (e) {
    alert(e);
  }
}

function check_status() {
  var user = $("#user").val();
  var realm = $("#realm").val();
  var pin = $("#pin").val();
  var transactionid = $("#transactionid").val();

  var params = {};
  params["user"] = user;
  if (realm != undefined) {
    params["realm"] = realm;
  }
  params["pass"] = pin;
  params["transactionid"] = transactionid;

  var url = "/validate/check_status";

  var resp = clientUrlFetchSync(url, params);
  var data = jQuery.parseJSON(resp);

  if (false === data.result.status) {
    alert(data.result.error.message);
  } else {
    if (true === data.result.value) {
      if (data.detail.transactions[transactionid]["received_tan"] === true) {
        if (data.detail.transactions[transactionid]["valid_tan"] === true) {
          alert("User successfully authenticated!");
        } else {
          alert("User rejected the authentication request");
        }
      } else if (
        data.detail.transactions[transactionid]["received_tan"] === false
      ) {
        alert("User did not authenticate yet!");
      } else {
        alert("Error during request! Check for challenge timeout...");
      }
    } else if ("detail" in data && "message" in data.detail) {
      alert(data.detail.message);
    } else {
      alert("Error during request! Check for challenge timeout...");
    }
  }
}

function submitChallengeResponse() {
  var user = $("#user").val();
  var realm = $("#realm").val();
  var otp = $("#otp").val();
  var transactionid = $("#transactionid").val();

  var params = {};
  params["user"] = user;
  if (realm != undefined) {
    params["realm"] = realm;
  }
  params["pass"] = otp;
  params["transactionid"] = transactionid;

  var url = "/validate/check";

  var resp = clientUrlFetchSync(url, params);
  var data = jQuery.parseJSON(resp);

  if (false == data.result.status) {
    alert(data.result.error.message);
  } else {
    if (true == data.result.value) {
      alert("User successfully authenticated!");
    } else if ("detail" in data && "message" in data.detail) {
      alert(data.detail.message);
    } else {
      alert("User failed to authenticate!");
    }
  }
}

function login_user(column) {
  var user = "";
  var pass = "";
  var realm = $("#realm").val();
  if (column == 3) {
    user = $("#user3").val();
    pass = encodeURIComponent($("#pass3").val() + $("#otp3").val());
  } else {
    user = $("#user").val();
    pass = $("#pass").val();
  }

  var params = {};
  params["user"] = user;
  if (realm != undefined) {
    params["realm"] = realm;
  }
  params["pass"] = pass;

  var resp = clientUrlFetchSync("/validate/check", params);
  var data = jQuery.parseJSON(resp);

  if (false == data.result.status) {
    alert(data.result.error.message);
  } else {
    if (true == data.result.value) {
      alert("User successfully authenticated!");
    } else if ("detail" in data && "message" in data.detail) {
      alert(data.detail.message);
    } else {
      alert("User failed to authenticate!");
    }
    //$('#user').val('');
    $("#pass").val("");
    $("#otp3").val("");
  }
}

$(document).ready(function () {
  $("button, input[type=submit]").button();

  /*
   * Auth login callbacks
   */

  // auth/index
  $("#form_login").submit(function (submit_event) {
    submit_event.preventDefault();
    login_user((column = 2));
  });

  // auth/index3
  $("#form_login3").submit(function (submit_event) {
    submit_event.preventDefault();
    login_user((column = 3));
  });

  // auth/qrtoken
  $("#form_challenge_trigger").submit(function (e) {
    e.preventDefault();
    triggerChallenge();
  });

  $("#form_challenge_submit").submit(function (e) {
    e.preventDefault();
    submitChallengeResponse();
  });

  $("#check_status").click(function (click_event) {
    check_status();
  });

  // auth/ocra2
  $("#form_challenge_ocra2").submit(function (submit_event) {
    submit_event.preventDefault();
    getOcra2Challenge();
  });

  $("#form_login_ocra2").submit(function (submit_event) {
    submit_event.preventDefault();
    login_user((column = 2));
  });
});
