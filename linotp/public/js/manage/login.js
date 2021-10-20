$(function () {
    $('#loginForm').ajaxForm({
        url: '/admin/login',
        type: 'post',
        datatype: 'json',
        success: loginSuccessCallback,
        error: loginErrorCallback
    });

    $('#login-box input:visible, #login-box a:visible').first().focus();

    loadTranslations();
});

function loginSuccessCallback(data, status) {
    if (status == "success" && data.result.value === true) {
        window.location.reload();
    } else {
        loginErrorCallback(data, status);
    }
}
function loginErrorCallback(data, status) {
    console.log("Login failed");
    alert(sprintf(
        i18n.gettext("Login failed. Reason: %s"),
        data.responseJSON.detail.message,
    ));
}
