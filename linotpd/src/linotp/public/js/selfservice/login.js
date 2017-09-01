var i18n = new Jed({});

$(function() {
    $('#loginForm').ajaxForm({
        url: '/userservice/login',
        type: 'post',
        success: ssLoginSuccessCallback,
        error: ssLoginErrorCallback
    });

    loadTranslations();
});

function ssLoginSuccessCallback(data, status) {
    if(data.result && data.result.value === true) {
        window.location.href = "/selfservice/";
    }
    else if(data.result && data.result.error) {
        alert(i18n.gettext("Login failed")
            + (data.result.error.message ? ": \n" + data.result.error.message : ""));
    }
    else {
        ssLoginGetChallenges();
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
        var template = $('<div/>', {id: "main"});
        $( "#template-tokenlist" ).clone().removeAttr("id").appendTo(template);

        var list = $('.list', template);

        window.tokens = data.result.value;
        if(tokens.length === 1) {
            ssLoginSelectToken(tokens[0]);
            return;
        }
        $.each(tokens, function(key, value) {
            var token = $( "#template-tokenlist-entry" ).clone().removeAttr("id");
            var type = value['LinOtp.TokenType'];
            var serial = value['LinOtp.TokenSerialnumber'];
            token.text(getTokenDescription(type) + " ("+serial+")");
            token.attr("data-token-number", key);
            list.append(token);
        });

        list.append($( "#template-cancel-entry" ).clone().removeAttr("id"));

        $('#main').replaceWith(template);

        $('.tokenlist-entry').click(ssLoginSelectTokenClickHandler);
        list.controlgroup({
            "direction": "vertical"
        });
    }
    else {
        alert(i18n.gettext("Error during login"));
    }
}

function ssLoginSelectTokenClickHandler() {
    ssLoginSelectToken(tokens[$(this).attr("data-token-number")]);
}

function ssLoginSelectToken(token) {
    $.ajax({
        url: '/userservice/login',
        type: 'post',
        data: {
            session: getcookie("user_selfservice"),
            serial: token['LinOtp.TokenSerialnumber'],
            data: i18n.gettext('Selfservice Login Request')
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

        var template = $('<div/>', {id: "main"});
        $( "#template-otp" ).clone().removeAttr("id").appendTo(template);

        if(type == "qr") {
            var qr = $( "#template-otp-qr" ).clone().removeAttr("id");
            $('.qr', qr).attr("src", data.detail.img_src);
            $('.qr', qr).attr("alt", data.detail.message);
            $('.method', template).append(qr);
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
        else {
            var push = $( "#template-otp-push" ).clone().removeAttr("id")
            $('.method', template).append(push);
        }
        $('#main').replaceWith(template);
    }
    else {
        alert(i18n.gettext("Error during login"));
    }
}

function ssLoginOTPCallback(data, status) {
    if(data.result && data.result.value === true) {
        window.location.href = "/selfservice/";
    }
    else {
        alert(i18n.gettext("OTP Validation failed"));
    }
}

function ssLoginErrorCallback() {
    alert(i18n.gettext("Connection Error during login"));
}

function getTokenDescription(type) {
    switch (type.toLowerCase()) {
        case "push":
            return i18n.gettext("Confirm using mobile");
        case "qr":
            return i18n.gettext("Scan QR code");
        case "hmac":
            return i18n.gettext("Enter OTP");
        case "totp":
            return i18n.gettext("Enter tOTP");
        case "motp":
            return i18n.gettext("Use mOTP token");
        case "email":
            return i18n.gettext("Send OTP by e-mail");
        case "sms":
            return i18n.gettext("Send OTP by SMS");
        case "yubico":
            return i18n.gettext("Use Yubikey");
    }
    return "";
}
