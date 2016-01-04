/*!
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
 *    E-mail: linotp@lsexperts.de
 *    Contact: www.linotp.org
 *    Support: www.lsexperts.de
 *
 */
function checkpins(otp_pin1,otp_pin2){
/*
 *  check pins: verifies, that the pins in both
 *  referenced entries are equal
 */
    var pin1 = $('#'+otp_pin1).val();
    var pin2 = $('#'+otp_pin2).val();
    if (pin1 == pin2) {
        $('#'+otp_pin1).removeClass('ui-state-error');
        $('#'+otp_pin2).removeClass('ui-state-error');
    }
    else {
        $('#'+otp_pin1).addClass('ui-state-error');
        $('#'+otp_pin2).addClass('ui-state-error');
    }
    return false;
}

function cb_changed(checkbox_id,arry){
/*
 * cb_changed - dependent on the checkbox state,
 * show all entries (identified by their id), which are listed in the array
 */
    var checked = $('#'+checkbox_id).is(':checked');

    for (i=0; i<arry.length; i++) {
        var sid = arry[i];
        if  ( checked )
            $('#'+sid).hide();
        else
            $('#'+sid).show();
    }
}
function cb_changed_deactivate(checkbox_id,arry){
/*
 * cb_changed - dependent on the checkbox state,
 * show all entries (identified by their id), which are listed in the array
 */
    var checked = $('#'+checkbox_id).is(':checked');

    for (i=0; i<arry.length; i++) {
        var sid = arry[i];
        if  ( checked ) {
            $('#'+sid).prop('disabled', true);
            $('#'+sid).addClass('disabled');
        } else {
            $('#'+sid).prop('disabled', false);
            $('#'+sid).removeClass('disabled');
        }
    }
}


function show_waiting() {
    $('#do_waiting').show();
    //$('#statusline').show();
    //var milliseconds = (new Date()).getTime();
    //console.log("show: " +milliseconds);
}

function hide_waiting() {
    $("#do_waiting").hide();
    //$('#statusline').hide();
    //var milliseconds = (new Date()).getTime();
    //console.log("hide: " +milliseconds);
}

function getcookie(search_key) {
    var searched_cookie="";
    if (document.cookie) {
        cookieArray = document.cookie.split(';');
        //alert(document.cookie);
        var arLen=cookieArray.length;
        for ( var i=0; i<arLen; ++i ) {
            var cookie = cookieArray[i];
            var key_1 = 0;
            var key_2 = cookie.indexOf("=");
            var val_1 = cookie.indexOf("=") + 1;
            var val_2 = cookie.indexOf(";");
            if(val_2 == -1) val_2 = document.cookie.length;

            var key = cookie.substring(key_1,key_2);
            key=key.replace(/^\s\s*/, '').replace(/\s\s*$/, '');
            key=key.replace(/^\""*/, '').replace(/\""*$/, '');

            if (search_key == key) {
                searched_cookie = cookie.substring(val_1,val_2);
                searched_cookie = searched_cookie.replace(/^\""*/, '').replace(/\""*$/, '');
            }
        }
    }
    return searched_cookie;
}

function console_log(msg) {
    var log_msg = escape(msg);
    if (window.console && window.console.log) {
        window.console.log(log_msg);
    }
    else if (window.opera && window.opera.postError) {
        window.opera.postError(log_msg);
    }
}


function entity_decode(msg) {
    var type = typeof msg;
    if (type == 'string') {
        msg = msg.replace(/&gt;/g, '>');
        msg = msg.replace(/&lt;/g, '<');
        msg = msg.replace(/&quot;/g, '"');
        msg = msg.replace(/&#39;/g, "'");
        msg = msg.replace(/&amp;/g, '&');
    }
    return msg;
}
function entity_encode(msg) {
    var type = typeof msg;
    if (type == 'string') {
        msg = msg.replace(/&/g, '&amp;');
        msg = msg.replace(/>/g, '&gt;');
        msg = msg.replace(/</g, '&lt;');
        msg = msg.replace(/"/g, '&quot;');
        msg = msg.replace(/'/g, '&#39;');
    }
    return msg;
}
/*
treewalk an json document and execute the callback on every leave
*/
function traverse(jData, callback) {
  var type = typeof jData;
    if (type == 'object') {
        for (var key in jData) {
            jData[key] = traverse(jData[key], callback);
        }
        return jData;
    } else {
        return callback(jData);
    }
}

function escape(data) {
	return traverse(data, entity_encode);
}

function descape(data) {
	return traverse(data, entity_decode);
}
