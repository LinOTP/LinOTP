var i18n = new Jed({});

var username;

$(function() {
    $('#loginForm').ajaxForm({
        url: '/userservice/login',
        type: 'post',
        success: ssLoginSuccessCallback,
        error: ssLoginErrorCallback
    });

    $('#login-box input:visible, #login-box a:visible').first().focus();

    loadTranslations();
});

function ssLoginSuccessCallback(data, status) {
    var secondStepMessage = "credential verified - additional authentication parameter required";
    if(data.result && data.result.value === true) {
        window.location.reload();
    }
    else if(data.result && data.result.error) {
        alert(i18n.gettext("Login failed")
            + (data.result.error.message ? ": \n" + data.result.error.message : ""));
    }
    else if(data.detail &&
            data.detail.message == secondStepMessage){
        username = $('#login').val();
        ssLoginGetChallenges();
    }
    else {
        alert(i18n.gettext("Login failed"));
    }
}

function ssLoginGetChallenges() {
    $.ajax({
        url: '/userservice/usertokenlist',
        type: 'post',
        data: {
            session: getcookie("user_selfservice"),
            active: true
        },
        success: ssLoginChallengesCallback,
        error: ssLoginErrorCallback
    });
}

function ssLoginChallengesCallback(data, status) {
    if(data.result && data.result.status === true) {
        var template = $('<div/>', {id: "login-box"});

        window.tokens = data.result.value;

        if(tokens.length === 0) {
            $( "#template-no-token-warning" ).clone().removeAttr("id").appendTo(template);
        }
        else if(tokens.length === 1) {
            ssLoginSelectToken(tokens[0]);
            return;
        }
        else {
            $( "#template-tokenlist" ).clone().removeAttr("id").appendTo(template);
            var list = $('.list', template);

            $.each(tokens, function(key, value) {
                var token = $( "#template-tokenlist-entry" ).clone().removeAttr("id");

                var type = value['LinOtp.TokenType'];
                var description = value['LinOtp.TokenDesc'];
                var serial = value['LinOtp.TokenSerialnumber'];

                $(".action", token).text(getTokenAction(type));
                $(".description", token).text(description + " ("+serial+")");
                token.attr("data-token-number", key);

                list.append(token);
            });

            $(document).keydown(function(e) {
                if (e.keyCode == 40) {
                    var entry = $("#login-box .tokenlist-entry:focus");
                    if(!entry.length)
                        entry = $("#login-box .tokenlist-entry:first").focus();
                    else
                       entry.next().focus();
                }
                if (e.keyCode == 38) {
                    var entry = $("#login-box .tokenlist-entry:focus");
                    if(!entry.length)
                        entry = $("#login-box .tokenlist-entry:last").focus();
                    else
                       entry.prev().focus();
                }
            });

            list.append($( "#template-cancel-entry" ).clone().removeAttr("id"));
        }
        $('#login-box').replaceWith(template);
        $('#login-box input:visible, #login-box a:visible').first().focus();

        $('.tokenlist-entry').click(ssLoginSelectTokenClickHandler);
    }
    else {
        alert(i18n.gettext("Error during login"));
    }
}

function ssLoginSelectTokenClickHandler() {
    $(document).unbind('keydown');
    ssLoginSelectToken(tokens[$(this).attr("data-token-number")]);
}

function ssLoginSelectToken(token) {
    $.ajax({
        url: '/userservice/login',
        type: 'post',
        data: {
            session: getcookie("user_selfservice"),
            serial: token['LinOtp.TokenSerialnumber'],
        },
        success: function(data, status) {
            ssLoginChallengeCallback(data, status, token);
        },
        error: ssLoginErrorCallback
    });
}

function ssLoginChallengeCallback(data, status, token) {
    if(data.result && data.result.status === true) {
        var type = token['LinOtp.TokenType'].toLowerCase();

        var template = $('<div/>', {id: "login-box"});
        $( "#template-otp" ).clone().removeAttr("id").appendTo(template);

        if(type == "qr") {
            if(!data.detail || !data.detail.img_src) {
                alert(i18n.gettext("Error during login"));
                return;
            }

            var qr = $( "#template-otp-qr" ).clone().removeAttr("id");
            $('.qr', qr).attr("src", data.detail.img_src);
            $('.qr', qr).attr("alt", data.detail.message);
            $('.method', template).append(qr);
        }


        if (type == "push"){
            var push = $( "#template-otp-push" ).clone().removeAttr("id")
            $('.method', template).append(push);
        }


        if (["push", "qr"].indexOf(type) != -1){
            if (!data.detail || !data.detail.transactionId) {
                alert(i18n.gettext("Error during login"));
                return;
            }

            var polling = $( "#template-otp-polling" ).clone().removeAttr("id")

            $('.transactionid', polling).text(data.detail.transactionId.slice(0, 6))

            $('.method', template).append(polling);
            ssLoginPolling();
        }

        if(type != "push") {
            var input = $( "#template-otp-input" ).clone().removeAttr("id")
            $('.method', template).append(input);

            $('form', input).ajaxForm({
                url: '/userservice/login',
                type: 'post',
                data: { session: getcookie("user_selfservice") },
                success: ssLoginOTPCallback,
                error: ssLoginErrorCallback
            });

            $('input[name="otp"]', input).attr("id", "otp");
        }

        $('#login-box').replaceWith(template);
        $('#login-box .method input:visible, #login-box .method a:visible').first().focus();
    }
    else {
        alert(i18n.gettext("Error during login"));
    }
}

function ssLoginOTPCallback(data, status) {
    if(data.result && data.result.value === true) {
        window.location.reload();
    }
    else {
        alert(i18n.gettext("OTP Validation failed"));
    }
}

function ssLoginPolling() {
    var intervalID = window.setInterval(function() {
        $.ajax({
            url: '/userservice/login',
            type: 'post',
            data: {
                session: getcookie("user_selfservice"),
            },
            success: function(data) {
                if (data.detail && (data.detail.accept || data.detail.valid_tan)) {
                    location.reload();
                }
                else if (data.detail && data.detail.status !== "open") {
                    ssLoginAbortPolling(intervalID);
                }
            },
            error: function() {
                ssLoginAbortPolling(intervalID);
                ssLoginErrorCallback();
            }
        });
    }, 3 * 1000);
}

function ssLoginAbortPolling(intervalID) {
    window.clearInterval(intervalID);

    var template = $('<div/>', {id: "login-box"});
    $( "#template-timeout" ).clone().removeAttr("id").appendTo(template);
    $('#login-box').replaceWith(template);

    setTimeout(function() {
        location.reload();
    }, 10000);
}

function ssLoginErrorCallback(data, status) {
    if (data.status == 401) {
        alert(i18n.gettext("Invalid session - please try again."));
        location.reload();
    } else {
        alert(i18n.gettext("Connection Error during login"));
    }
}

function getTokenAction(type) {
    switch (type.toLowerCase()) {
        case "push":
            return i18n.gettext("Confirm using mobile");
        case "qr":
            return i18n.gettext("Scan QR code");
        case "hmac":
            return i18n.gettext("Enter OTP");
        case "totp":
            return i18n.gettext("Enter TOTP");
        case "motp":
            return i18n.gettext("Use mOTP token");
        case "email":
            return i18n.gettext("Send OTP by e-mail");
        case "sms":
            return i18n.gettext("Send OTP by SMS");
        case "yubikey":
        case "yubico":
            return i18n.gettext("Use Yubikey");
        case "voice":
            return i18n.gettext("Send OTP by voice call");
    }
    return i18n.gettext("Enter OTP");
}
