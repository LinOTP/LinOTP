/*!
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
 *    E-mail: linotp@keyidentity.com
 *    Contact: www.linotp.org
 *    Support: www.keyidentity.com
 *
 */

 /**
  * checkpins compares the values of the inputs given via
  * the jquery selector or object and visualizes the result
  * via ui-state-error class
  * @param {Object|string} pin_inputs - an selector or jQuery object referencing all inputs to compare
  * @returns Boolean
  */
function checkpins(pin_inputs){
    var pins = $(pin_inputs)
        .map(function(){return $(this).val();}).get();

    if(array_entries_equal(pins)) {
        $(pin_inputs).removeClass('ui-state-error');
        return true;
    }
    else {
        $(pin_inputs).addClass('ui-state-error');
        return false;
    }
}

/**
 * array_entries_equal returns true if all entries of 'array' are equal
 * @oaram {Array} array - the unit under test
 * @return {Boolean}
 */
function array_entries_equal(array) {

    if(!$.isArray(array)) {
        throw "array_entries_equal expects an array as param";
    }

    if(array.length > 1) {
        for(var i = 1; i < array.length; i++) {
            if(array[i] !== array[0]) {
                return false;
            }
        }
    }
    return true
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
}

function hide_waiting() {
    $("#do_waiting").hide();
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


/**
 * tests object for the existance of a given key
 * or chain of keys for nested search
 * @param  {Object}                object the haystack to search in
 * @param  {String|Array<String>}  key    the name of the key(s) to search from
 * @return {Boolean}                      true if key exists in object
 */
function isDefinedKey(object, key){
    if(key.constructor !== Array) key = [key]; // make sure the key is wrapped in an array or wrap it
    if(object !== null && key.length > 0) {
        var result = object.hasOwnProperty(key[0]);
        if(key.length == 1) {
            return result;
        }
        // if object has the first part of the key, search this object with the rest of the key
        return (result ? isDefinedKey(object[key.shift()], key) : false);
    }
    return false;
}

/**
 * parses the linotp version string to a unified presentation
 * of minor release level that can be compared.
 * @param  {String} linotp_version the version string containing product name and version number
 * @return {String}                the version number containing generation, major and minor
 *                                 releases and not patch and dev releases
 */
function parseMinorVersionNumber(linotp_version) {

    // the expectation is, that the version number does not
    // contain any spaces, the product name may eventually
    var versionNumber = linotp_version.substring(linotp_version.lastIndexOf(" ") + 1).split(".");

    // fill array with equivalent value of non existant
    while(versionNumber.length < 3) versionNumber.push("0");

    // "ignore" dev releases
    for(var i = 0; i < versionNumber.length; i++) {
        if(versionNumber[i].indexOf("dev") === 0) {
            versionNumber[i] = "0";
        }
    }

    return versionNumber.slice(0,3).join(".");
}

/**
 * parses the linotp version string to a unified presentation
 * of major release level that can be compared.
 * @param  {String} linotp_version the version string containing product name and version number
 * @return {String}                the version number containing generation and major relases
 *                                 not minor, patch and dev releases
 */
function parseMajorVersionNumber(linotp_version) {

    // the expectation is, that the version number does not
    // contain any spaces, the product name may eventually
    var versionNumber = linotp_version.substring(linotp_version.lastIndexOf(" ") + 1).split(".");

    // fill array with equivalent value of non existant
    while(versionNumber.length < 3) versionNumber.push("0");

    // "ignore" dev releases
    for(var i = 0; i < versionNumber.length; i++) {
        if(versionNumber[i].indexOf("dev") === 0) {
            versionNumber[i] = "0";
        }
    }

    return versionNumber.slice(0,2).join(".");
}

/**
 * compares two version number strings containing nummerical values joined by dots
 * @param  {String} v1 first version number
 * @param  {String} v2 second version number
 * @return {Number}    1 if first, -1 if second version number is greater or 0 if they are equal
 */
function compareVersionNumbers(v1, v2) {
    var v1parts = v1.split("."), v2parts = v2.split(".");

    while (v1parts.length < v2parts.length) v1parts.push("0");
    while (v2parts.length < v1parts.length) v2parts.push("0");

    v1parts = $.map(v1parts, Number);
    v2parts = $.map(v2parts, Number);

    for(var i = 0; i < v1parts.length; i++) {
        if(v1parts[i] > v2parts[i]) return 1;
        if(v1parts[i] < v2parts[i]) return -1;
    }

    return 0;
}