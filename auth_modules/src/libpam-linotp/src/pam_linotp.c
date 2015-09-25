/*
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2015 LSE Leading Security Experts GmbH
 *       Author: Niklas Abel 08.2015
 *
 *   This file is part of LinOTP authentication modules.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *    E-mail: linotp@lsexperts.de
 *    Contact: www.linotp.org
 *    Support: www.lsexperts.de
 *
 */

/*******************************************************************
 *   pam_linotp - pam authentication with your otp against linotp
 *******************************************************************

 * create a
    /etc/pam.d/common-linotp

 * with the following content

    auth    [success=1 default=ignore] pam_linotp.so \
        url=http://linotpserver/validate/simplecheck noosslhostnameverify nosslcertverify \
        realm=mydefrealm

   or

    auth    [success=1 default=ignore] pam_linotp.so \
        url=https://linotpserver/validate/simplecheck ca_file=/etc/ssl/ssl.crt/linotp-ca.cer \
        realm=mydefrealm

	and deploy the CA-file into folder /etc/ssl/ssl.crt/

 *
 * parmeters are here:
 *
 *  pam_linotp.so           - the module ref, which should be in /lib/security
 *                            in most cases
 *  url=https://l...        - the reference to your linotp server
 *  realm=..                - the default realm, where the user is to be searched
 *  ca_file=fullpath-cafile - added support for sslopt CURLOPT_CAINFO. This option
 *                            is not needed on MacOS installations. There, the
 *                            certificate must be installed in System-Key-Store.
 *  ca_path=fullpath-cadir  - added support for sslopt CURLOPT_CAPATH
 *  noosslhostnameverify    - when using ssl, switch the ssl host verification off
 *  nosslcertverify         - when using ssl, switch the ssl cert verification off
 *  tokenlength=4,6,8       - the possible used token length, sepperated with ","
 *                            the token config has to be ordered by size
 *  use_first_pass          - sets the PAM module to use password from stack
 *                            only use use_fist_pass for GUI login, because there
 *                            the PAM module hat to use the password from stack
 *
 *  prompt=OTP:             - defines prompt text, default text is "Your OTP:"
 *
 *  debug                   - shows additional login infromation
 *
 * in your /etc/pam.d/ files you can include the linotp authenication by adding
 * the following line:
 *

@include common-linotp

 *

 This is a derived work from:
 http://www.freebsd.org/doc/en/articles/pam/pam-sample-module.html

 *****************************************************************************/
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <dirent.h>

#include "zeromem.h"

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <syslog.h>
#include <ctype.h>

#include <curl/curl.h>

#ifdef pam_prompt
/* Fedora needs this */
#include <security/pam_ext.h>
#endif

#define PAM_LINO_CHALLENGE 99
#define LINOTPD_OK         ":-)"
#define LINOTPD_REJECT     ":-("
#define LINOTPD_FAIL       ":-/"

#define MAXMEMSIZE         1024 * 1024

/* config enries maxlen */
#define URLMAXLEN    1000
#define REALMMAXLEN   100
#define RESMAXLEN     100
#define TOKENMAXLEN   100

/*****************************************************************************/

static char password_prompt[] = "Your OTP: ";
int debugflag = 0;

/*
 config options which could be set in the pam configuration:
      url=http://localhost:5001/validate/simplecheck
      nosslhostnameverify
      nosslcertverify
      realm
      resConf
      debug
 */


typedef struct {
    char * url;
    int nosslhostnameverify;
    int nosslcertverify;
    char * realm;
    char * resConf;
    int use_first_pass;
    int debug;
    char * prompt;
    char * tokenlength;
    char * ca_file;
    char * ca_path;
} LinOTPConfig ;

int pam_linotp_get_authtok(pam_handle_t *pamh, char **password, char ** cleanpassword,
        const char * prompt, int use_first_pass, size_t *token_length);

int pam_local_get_authtok(pam_handle_t *pamh, int item, char **password,
        char * prompt, int use_first_pass);

int pam_linotp_validate_password(pam_handle_t *pamh,
        char *user, char *password,
        LinOTPConfig *config);

int pam_prompt(const pam_handle_t *_pamh, int _style, char **_resp, const char *_fmt, ...);

/************** syslog stuff **********************/

static void do_log(int type, char * format, ...) {
    if(debugflag){
        va_list args;
        va_start(args, format);
        openlog("pam_linotp", LOG_PID, LOG_AUTHPRIV);
        vsyslog(type, format, args);
        closelog();
        va_end(args);
    }
}

#ifdef DEBUG
#define log_error(format, ...)   do_log(LOG_ERR,    "linotp:ERROR: "   #format, ## __VA_ARGS__)
#define log_debug(format, ...)   do_log(LOG_ERR,    "linotp:DEBUG: "   #format, ## __VA_ARGS__)
#define log_warning(format, ...) do_log(LOG_ERR,    "linotp:WARNING: " #format, ## __VA_ARGS__)
#define log_info(format, ...)    do_log(LOG_ERR,    "linotp:INFO: "    #format, ## __VA_ARGS__)
#else
#define log_error(format, ...)   do_log(LOG_ERR,     "linotp:ERROR: "   #format, ## __VA_ARGS__)
#define log_debug(format, ...)   do_log(LOG_DEBUG,   "linotp:DEBUG: "   #format, ## __VA_ARGS__)
#define log_warning(format, ...) do_log(LOG_WARNING, "linotp:WARNING: " #format, ## __VA_ARGS__)
#define log_info(format, ...)    do_log(LOG_INFO,    "linotp:INFO: "    #format, ## __VA_ARGS__)
#endif

static char * erase_data(void * data, size_t len) {
    if(!data){
        return NULL;
    }
    /* wipe all data and free the memory */
    int ret = EINVAL;
    ret = memset_s(data, len, 0, len);
    if(ret!=0){
        log_warning("memset_s failed, using memset instead! (ERROR: %d)",ret);
        memset(data, len, len);
        if(ret == E2BIG) {
            if(len > SIZE_MAX) {
                log_error(
                "ERROR: %s()[%s:%d] memset_s argument len or is greater than the \
                <stdint.h> defined SIZE_MAX.  Something is really wrong here!",
                __FUNCTION__, __FILE__, __LINE__ );
            }
        }
    }
    free(data);
    return NULL;
}

static char * erase_string(char * string) {
    /* wipe all data and free the memory */
    if(string && *string){
            return erase_data(string, strlen(string));
    }
    return NULL;
}

/***********************************************
 Curl stuff
 ***********************************************/
struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t curl_write_memory_callback(void *ptr, size_t size, size_t nmemb,
        void *data) {
    /***
     * this the curl write callback function:
     *  from::  http://curl.haxx.se/libcurl/c/curl_easy_setopt.html
     *
     CURLOPT_WRITEFUNCTION
    Pass a pointer to a function that matches the following prototype:

        size_t function( char *ptr, size_t size, size_t nmemb, void *userdata);

    This function gets called by libcurl as soon as there is data received that
    needs to be saved. The size of the data pointed to by ptr is size multiplied
    with nmemb, it will not be zero terminated.

    Return the number of bytes actually taken care of.
    If that amount differs from the amount passed to your function, it'll signal
    an error to the library. This will abort the transfer and return CURLE_WRITE_ERROR.

    This function may be called with zero bytes data if the transferred file is
    empty.

    Set the userdata argument with the CURLOPT_WRITEDATA option.

    The callback function will be passed as much data as possible in all invokes,
    but you cannot possibly make any assumptions. It may be one byte, it may be
    thousands. The maximum amount of body data that can be passed to the write
    callback is defined in the curl.h header file: CURL_MAX_WRITE_SIZE (the usual
    default is 16K). If you however have CURLOPT_HEADER set, which sends header
    data to the write callback, you can get up to CURL_MAX_HTTP_HEADER bytes of
    header data passed into it. This usually means 100K.*
     *
     */

    struct MemoryStruct *mem = (struct MemoryStruct *) data;
    long long int protectit;
    protectit = (size_t)(size * nmemb);
    size_t realsize = (size_t) protectit;
    if(realsize != protectit){
        log_debug("Integer overflow detected @ curl_write_memory_callback");
        return 0;
    }
    char *tmp;

    /*Check for Max_size*/
    if (realsize > MAXMEMSIZE) {
        log_error(
                "ERROR: The linotpd responded to our authentication "\
                "request with more than 1MB of data! Something is really "\
                "wrong here!");

        return mem->size;
    }
    /* do the alloc or realloc*/
    tmp = realloc(mem->memory, mem->size + realsize + 1);
    if (!tmp) {
        /* wipe and free */
        mem->memory = erase_data(mem->memory, mem->size);
        mem->size = 0;
        log_error("re-allocation during the write memory callback failed!");
        return 0;
    }
    mem->memory = tmp;
    memcpy(&(mem->memory[mem->size]), ptr, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

/*************************************************************************
 * linotp utils - to manage the linotp request and response
 *************************************************************************/
void linotp_split_stat_and_message(char * s, char ** stat, char ** msg)
{
    /*
    in case of a challenge request, the reply of the linotp server
    contains after the not-smily, the stat - transaction reference
    and then arbitrary, non defined message, which is displayed to
    the user.
    this method splits out the return value the stat and the message
    and returns them by reference.

    */
    *stat = (char *) "";
    *msg = (char *) "";

    char * fin = NULL;

    /* return, if there is nothing more than an ok */
    if (strlen(LINOTPD_OK) >= strlen(s)){
        return;
    }

    fin = strchr(s+strlen(LINOTPD_REJECT), ' ');
    if (!fin){
        return;
    }

    /*now search start of stat */
    while(*fin != '\0') {
        if (*fin == ' ')
            fin++;
        else
            break;
    }
    if (*fin == '\0') return;

    /* preserve the start of the stat*/
    *stat = (char *) fin;

    /* find the next blank after the stat */
    fin = strchr(fin, ' ');
    if (fin == NULL) return;

    /* mark the terminating of stat, the rest is msg*/
    *fin = '\0';
    fin++;
    if (*fin != '\0') *msg = (char *) fin;

    return;
}
char * linotp_create_url_params(CURL *curl_handle, int number_of_pairs, ...)
{
    /*
    doing a post request requires for curl to have all the parameters
    concatenated into one string, where the parameters are seperated
    by & and the key/value by the '=' sign

        realm=myrealm&user=me

    if a parameter value is NULL or has no length, it won't be appended

    the number of key value pairs has to be reflected by the number_of_pairs counter

    all parameter values are first url escaped and will be freed after
    the concatenation.
    */
    unsigned int i = 0;
    size_t size = 0;

    /*** initialize array****/
    char * arry[number_of_pairs][2];
    memset(arry, 0, sizeof(arry));

    /* the return value */
    char *param = NULL;

    log_debug("entering linotp_create_url_params.");

    va_list ap;
    va_start(ap, number_of_pairs);

    i = 0;
    int count = 0;
    while (count < number_of_pairs){
        char * key = va_arg(ap, char *);
        char * val = va_arg(ap, char *);
        if ((val != NULL) && (strlen(val) > 0)) {
            arry[i][0] = curl_easy_escape(curl_handle, key, 0);
            arry[i][1] = curl_easy_escape(curl_handle, val, 0);
            size = size + strlen(arry[i][0]) + strlen(arry[i][1]) + strlen("&=");
            i++;
        }
        count++;
    }
    /* preserve space for the terminating \0 */
    size = size +1;
    log_debug("allocating %d chars", size);
    param = (char*) calloc(size, sizeof(char));
    if(!param){
        log_debug("ERROR: calloc param in linotp_create_url_params failed");
        va_end(ap);
        return NULL;
    }
        /* concat the values in the param string*/
    for (i= 0; i< number_of_pairs; i++){

        if (arry[i][0] != NULL && arry[i][1] != NULL) {
            if (i>0) strcat(param,"&");
            strcat(param, arry[i][0]);
            strcat(param, "=");
            strcat(param, arry[i][1]);

            /* finally clean up the escaped data*/
            log_debug("freeing escaped value for %s", arry[i][0]);

            /* erase the data - so no pass etc. will be in memory */
            erase_data(arry[i][0], strlen(arry[i][0]));
            erase_data(arry[i][1], strlen(arry[i][1]));
        }
    }
    va_end(ap);
    return param;
}


int linotp_send_request(CURL *curl_handle, char * url, char * params,
        struct MemoryStruct * chunk,
        int nosslhostnameverify, int nosslcertverify,
        char * ca_file, char * ca_path) {
    /**
     *  submit an http request using curl to linotp
     *
     *  :param curl_handle: the curl handler
     *  :param url: the linotp url
     *  :param params: the POST parameters
     *  :param chunk: the result memory chunk
     *  :param nosslhostnameverify: ssl w. or wo. ssl hostname verify
     *  :param nosslcertverify: ssl w. or wo. ssl cert verify
     *
     *  :return: success status
     */
     int status = 0;
    /* Setup the base url */
    status = curl_easy_setopt(curl_handle, CURLOPT_URL, url);
    if(CURLE_OK != status) {
        log_error("curl_easy_setopt CURLOPT_URL from linotp_send_request failed");
        goto cleanup;
    }

    /* Now specify the POST data */
    status = curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, params);
    if(CURLE_OK != status) {
        log_error("curl_easy_setopt CURLOPT_POSTFIELDS from linotp_send_request failed");
        goto cleanup;
    }

    status = curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION,
            curl_write_memory_callback);
    if(CURLE_OK != status) {
        log_error("curl_easy_setopt CURLOPT_WRITEFUNCTION from linotp_send_request failed");
        goto cleanup;
    }

    status = curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, chunk);
    if(CURLE_OK != status) {
        log_error("curl_easy_setopt CURLOPT_WRITEDATA from linotp_send_request failed");
        goto cleanup;
    }

    status = curl_easy_setopt(curl_handle, CURLOPT_USERAGENT,
            "libcurl-pam-agent/1.0");
    if(CURLE_OK != status) {
        log_error("curl_easy_setopt CURLOPT_USERAGENT from linotp_send_request failed");
        goto cleanup;
    }

    if (nosslhostnameverify)
        status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
    else
        status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 2L);
    if(CURLE_OK != status) {
        log_error("curl_easy_setopt CURLOPT_SSL_VERIFYHOST from linotp_send_request failed");
        goto cleanup;
    }

    if (nosslcertverify)
        status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
    else
        status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);
    if(CURLE_OK != status) {
        log_error("curl_easy_setopt CURLOPT_SSL_VERIFYPEER from linotp_send_request failed");
        goto cleanup;
    }

    if (ca_file != NULL && strlen(ca_file) > 0) {
        status = curl_easy_setopt(curl_handle, CURLOPT_CAINFO, ca_file);
        if(CURLE_OK != status) {
            log_error("curl_easy_setopt CURLOPT_CAINFO from linotp_send_request failed");
            goto cleanup;
        }
    }

    if (ca_path != NULL && strlen(ca_path) > 0) {
        status = curl_easy_setopt(curl_handle, CURLOPT_CAPATH, ca_path);
        if(CURLE_OK != status) {
            log_error("curl_easy_setopt CURLOPT_CAPATH from linotp_send_request failed");
            goto cleanup;
        }
    }

    status = curl_easy_perform(curl_handle);
    if(CURLE_OK != status) {
        log_error("curl_easy_perform from linotp_send_request failed");
        goto cleanup;
    }

cleanup:
    curl_easy_cleanup(curl_handle);
    return status;
}
/********** LinOTP stuff ***************************/
int linotp_auth(char *user, char *password,
        LinOTPConfig *config, char ** state, char ** challenge,
        char * ca_file, char * ca_path) {
    /**
     * do the authentication check against linotp
     *
     * :param user: the user
     * :param user: the password
     * :param config: the configuration parameters
     * :param state: (in and out !!) the state id of a challenge response handshake
     * :param challenge: (out) the state id of a challenge response handshake
     */
    CURL *curl_handle = NULL;
    int returnValue = PAM_AUTH_ERR;
    char *param = NULL;
    CURLcode all_status = 0;

    *challenge = (char *) "";

    char errorBuffer[CURL_ERROR_SIZE];

    struct MemoryStruct chunk;
    chunk.memory = NULL;         /* we expect realloc(NULL, size) to work */
    chunk.size = 0;             /* no data at this point */

    curl_global_init(CURL_GLOBAL_ALL);

    curl_handle = curl_easy_init();

    if (curl_handle == NULL ) {
        log_error("could not get curl_handle!");
        returnValue = PAM_AUTH_ERR;
        goto cleanup;
    }

    curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, errorBuffer);

    param = linotp_create_url_params(curl_handle, 5,
            "realm",   config->realm,
            "resConf", config->resConf,
            "user",    user,
            "pass",    password,
            "state",  *state);

    if (param == NULL) {
        log_error("could not allocate size for url");
        goto cleanup;
    }

    if (config->debug) {
        log_debug("connecting to url:%s with parameters %s", config->url, param);
    }
    all_status = linotp_send_request(curl_handle, config->url, param, (void *) &chunk,
            config->nosslhostnameverify, config->nosslcertverify, ca_file, ca_path);

    if (config->debug) {
        log_debug("result %s", chunk.memory);
    }

    if (all_status != 0) {
        log_error("Error talking to linotpd server at %s: %s", config->url,
                errorBuffer);
        returnValue = PAM_AUTHINFO_UNAVAIL;
        goto cleanup;
    }
    if (chunk.memory == NULL ) {
        log_error("No response returned for %s: %s", config->url, errorBuffer);
        returnValue = PAM_AUTH_ERR;
        goto cleanup;
    }
    if (strcmp(chunk.memory, LINOTPD_REJECT) == 0) {
        log_info("user '%s' rejected", user);
        returnValue = PAM_AUTH_ERR;
        goto cleanup;
    }
    if (strncmp(chunk.memory, LINOTPD_REJECT, strlen(LINOTPD_FAIL)) == 0) {
        log_debug("Challenge authentication for '%s'::%.10s", user, chunk.memory);
        returnValue = PAM_LINO_CHALLENGE;
        char * stat = "";
        char * msg = "";

        linotp_split_stat_and_message(chunk.memory,&stat,&msg);

        /* we have to create duplicates, as they start as pointers into the
         * chunk memory, which will be freed at the end of this function
         * */
        log_info("Challenge authentication:'%.8s...' '%.8s...'",
                                                        *challenge, *state);
        /* msg and stat are never NULL*/
        *challenge = strdup(msg);
        *state = strdup(stat);
        if(!(*state)){
            erase_string(*challenge);
        }
        if ((*challenge) || (*stat)) {
            log_error("strdup failed during linotp_auth!");
            returnValue = PAM_ABORT;
        } else
            log_info("Challenge authentication:'%.8s...' '%.8s...'",
                                                        *challenge, *state);
        goto cleanup;
    }
    if (strcmp(chunk.memory, LINOTPD_FAIL) == 0) {
        log_warning("Authentication for '%s' failed", user);
        returnValue = PAM_AUTH_ERR;
        goto cleanup;
    }
    if (strcmp(chunk.memory, LINOTPD_OK) == 0) {
        log_info("User '%s' authenticated successfully\n", user);
        returnValue = PAM_SUCCESS;
        goto cleanup;
    }
    // default
    log_error("An error occured for '%s' on '%s'\n %.10s\n", user,
            config->url,chunk.memory);
    returnValue = PAM_AUTH_ERR;

    cleanup:
    chunk.memory = erase_data(chunk.memory, chunk.size);
    chunk.size = 0;
    param = erase_string(param);

    /* we're done with libcurl, so clean it up */
    curl_global_cleanup();

    return (returnValue);
}

int check_prefix(const char *text, const char *prefix, char **rest) {
    /**
     * Checks prefix with case insensitive comparison
     *
     * :param text: text to compare with
     * :param prefix: String of configuration name we are looking for
     * :param rest: result of searched configuration
     * :return: returns the length of prefix (offset of rest)
     */

    int lenprefix = 0;
    if(prefix){
        lenprefix = strlen(prefix);
    }

	if (!lenprefix || strncasecmp(text, prefix, lenprefix) != 0) {
        /* If prefix was empty or not found, then return 0*/
		if (rest != NULL) {
            *rest = NULL;
        }
        return 0;
    }
    if (rest) {
        *rest = (char*)text + lenprefix;
    }
    /* returns the length of prefix (offset of rest)...*/
    return lenprefix;
}

int pam_linotp_get_config(int argc, const char *argv[], LinOTPConfig * config, int debugflag_pam) {
    /*
     * now check the config options:
     *  config options to be set in the pam configuration:
     *  url=http://localhost:5001/validate/simplecheck
     *  nosslhostnameverify
     *  nosslcertverify
     *  realm=<yourRealm>
     *  resConf=<specialResolverConfig>
     *  use_first_pass - use the first parameters as pass
     *  debug - print out debug switch
     *
     *  :param config: struct with LinOTP configuration
     *  :param debugflag_pam: flag, if PAM asked to be silent (1 == please be silent)
     */

    int ret = PAM_SUCCESS;

    /* reset configuration */
    config->nosslhostnameverify = 0;
    config->nosslcertverify = 0;
    /*'use_first_pass', we will try to get the password from the pam stack."*/
    config->use_first_pass = 0;
    config->url = NULL;
    config->realm = NULL;
    config->resConf = NULL;
    config->use_first_pass = 0;
    config->debug = 0;
    config->prompt = strdup(password_prompt);
    config->tokenlength=0;
    config->ca_file=NULL;
    config->ca_path=NULL;
    unsigned int i = 0;

    for ( i = 0; i < argc; i++ ) {
        char *temp;
        if (strcasecmp(argv[i], "debug") == 0) {
            config->debug = 1;
            debugflag  = 1;
        } else if (strcasecmp(argv[i], "use_first_pass") == 0) {
            config->use_first_pass = 1;
        }
        /* check for validate url */
        else if (check_prefix(argv[i], "url=", &temp) > 0) {
            // this is the validateurl
            if (strlen(temp) > URLMAXLEN) {
                log_error("Your url is to long: %s (max %d)", argv[i],
                        URLMAXLEN);
                return (PAM_AUTH_ERR);
            } else {
                config->url = temp;
            }

        }
        /* check for realm */
        else if (check_prefix(argv[i], "realm=", &temp) > 0) {
            if (strlen(temp) > REALMMAXLEN) {
                log_error("Your realmname is to long: %s (max %d)", argv[i],
                        REALMMAXLEN);
                return (PAM_AUTH_ERR);
            } else {
                config->realm = temp;
            }
        }
        /* check for resolver */
        else if (check_prefix(argv[i], "resConf=", &temp) > 0) {
            if (strlen(temp) > RESMAXLEN) {
                log_error("Your resolver config name is to long: %s", argv[i]);
                return (PAM_AUTH_ERR);
            } else {
                config->resConf = temp;
            }
        }
        /*check for SSL options*/
        else if (strcasecmp(argv[i], "nosslhostnameverify") == 0) {
            config->nosslhostnameverify = 1;
        }
        else if (strcasecmp(argv[i], "nosslcertverify") == 0) {
            config->nosslcertverify = 1;
        }
        else if (check_prefix(argv[i], "CA_file=", &temp) > 0) {
            config->ca_file = temp;
        }
        else if (check_prefix(argv[i], "CA_path=", &temp) > 0) {
            config->ca_path = temp;
        }
        /* check for tokenlength */
        else if (check_prefix(argv[i], "tokenlength=", &temp) > 0) {
            if (strlen(temp) > TOKENMAXLEN) {
                log_error("Your token config length is to long: %s", argv[i]);
                return (PAM_AUTH_ERR);
            } else {
                config->tokenlength = temp;
            }
        }
        /* check for prompt */
        else if (check_prefix(argv[i], "prompt=", &temp) > 0) {
            if (strlen(temp) > RESMAXLEN) {
                log_error("Your prompt definition is to long: %s [%]", argv[i], RESMAXLEN);
                return (PAM_AUTH_ERR);
            } else {
                config->prompt = temp;
            }
        }
        else {
            log_debug("unkown configuration prameter %s", argv[i]);
        }

        /* if PAM asked for to be silent, disable debugging messages */
        if(1 == debugflag_pam){
            if(config->debug==1){
                debugflag  =1;
            } else {
                debugflag = 0;
            }
        }

    }
    if (config->debug) {
        log_debug("realm: %s",        config->realm);
        log_debug("resConf: %s",      config->resConf);
        log_debug("validate url: %s", config->url);
        log_debug("ca_file: %s",      config->ca_file);
        log_debug("ca_path: %s",      config->ca_path);
        log_debug("prompt: %s",       config->prompt);

        log_debug("'use_first_pass' %d ,", config->use_first_pass);
        if (config->use_first_pass > 0) {
            log_debug(" - we will try to get the password from the pam stack.");
        }
        log_debug("nosslhostnameverify %d", config->nosslhostnameverify);
        if (config->nosslhostnameverify == 1) {
            log_debug("we will not verify the hostname.");
        }
        log_debug("nosslcertverify %d", config->nosslcertverify);
        if (config->nosslcertverify == 1) {
            log_debug("found 'nosslcertverify', we will not verify the certificate.");
        }
    }
    return ret;
}

/*****************************************************
 * worker function to make the pam callback smaller ;-)
******************************************************/
int pam_linotp_validate_password(pam_handle_t *pamh,
        char *user, char *password,
        LinOTPConfig *config)
{    /**
     * validate the password against linotp
     * - the password could be an pin only, which then triggers an challenge
     * :param pamh: the pam handle
     * :param user: the user to be verified
     * :param password: the password to be checked
     * :param linOTPConfig: the linotp pam config entries
     *
     * :return: int for success, etc.
     */
    log_debug("pam_linotp_validate_password");
    log_debug("user: %s", user);
    log_debug("url : %s", config->url);
    if (config->ca_path && *(config->ca_path) != '\0') {
        log_debug("with ca_path: %s", config->ca_path);
    }

    char * state = NULL;
    char * challenge  = NULL;

    int ret = linotp_auth(user, password, config, &state, &challenge, config->ca_file, config->ca_path);
    if (ret != PAM_LINO_CHALLENGE){
        erase_string(state);
        erase_string(challenge);
        return ret;
    }

    /**
     * we are in challenge mode: ask for a response to the challenge
     **/
    log_debug("we are in challenge mode: %d", ret);

    if (config->debug)
        log_debug("challenge >%.10s< >%.10s< ", challenge, state);

    char * response = NULL;
    char * cleanresponse = NULL;
    ret = pam_linotp_get_authtok(pamh, &response, &cleanresponse, challenge, 0, 0);

    /* now the challenge is done, we can clean the dishes
     * :: challenge is not more required, but state is used as
     *    input to reference the transaction */
    if (config->debug)
        log_debug("free challenge: %.10s" , challenge);
    challenge = erase_string(challenge);

    if (config->debug)
        log_debug("submitting challenge response: %s ", response);

    ret = linotp_auth(user, response, config, &state, &challenge, config->ca_file, config->ca_path);

    if (config->debug)
        log_debug("reply to response of challenge >%.10s< state >%.10s< : %d",
             challenge, state, ret);

    if (config->debug) {
        log_debug("free state: %s" , state);
        log_debug("free response: %s" , response);
    }
    state = erase_string(state);
    response = erase_string(response);

    log_debug("all memory freed");

    return ret;
}

typedef struct _int_array {
    int* buff;
    size_t length;
} int_array;

int_array get_possibtok(char* token_length){
    /** Method to convert the configured token_length string into an int array.
     *
     * :param token_length: String of configured token_lenths
     *
     * :return: struct with an int array of token lengths,
     *          if there are no configured token legths,
     *          it returns an struct with length 0.
     */

    int_array ret;
    ret.buff   = NULL;
    ret.length = 0;

    int_array error;
    error.buff = NULL;
    error.length = 0;


     /* returns an integer array with parsed digits from string */
    if (!token_length) {
        ret.buff    = malloc(sizeof(int));
        if(!ret.buff){
            log_error("malloc ret.buff in get_possibtok failed");
            return error;
        }
        ret.length  = 1;
        ret.buff[0] = 0;
        return ret;
    }

    size_t len = strlen(token_length);
    int*   tmp = malloc(len * sizeof(int)); // allocate enough data...
    if(!(tmp)){
        log_error("malloc tmp in get_possibtok failed");
        return error;
    }
    int sep = -1;
    int cnt = 0;
    int val = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        if (isdigit(token_length[i])) {
            /* a Digit... */
            if (sep < 0) {
                /* token present, empty spaces are not ignored anymore... */
                sep = 0;
            } else if (sep > 0) {
                /* Ups, separator expected; Abort scan... */
                break;
            }


            val = val * 10 + (token_length[i] - '0');
        } else if (token_length[i] == ',' ||
                   token_length[i] == ';') {
            /* Token separator... */
            if (cnt > 0 && tmp[cnt - 1] >= val) {
                /* Ups, length list not sorted; Abort scan... */
                break;
            }

            tmp[cnt++] = val; /* new length value... */
            val = 0;
            sep = -1;
        } else if (isblank(token_length[i]) && sep == 0) {
            /* empty space after value will require a token separator... */
            sep = 1;
        } else {
            /* unexpected token; Abort scan... */
            break;
        }
    }
    if (sep >= 0) {
        if (cnt == 0 || tmp[cnt - 1] < val) {
            tmp[cnt++] = val;
        }
    }

    if (cnt > 0) {
        ret.buff   = malloc(cnt * sizeof(int));
        if(!ret.buff){
            log_error("malloc ret.buff in get_possibtok failed");
            int buff = 0;
            ret.buff = &buff;
            return ret;
        }
        ret.length = cnt;
        int k;
        for (k = 0; k < cnt; k++)
            ret.buff[k] = tmp[k];
    }

    erase_data(tmp, len * sizeof(int));
    return ret;
}

int pam_linotp_extract_authtok(
        pam_handle_t *pamh,
        char **password,
        char **cleanpassword,
        size_t *token_length)
{
    /* Received password from stack using first_pass, so we have to extract
    the otp and write the clean password back to the stack */
    int n = 6;
    int ret = PAM_AUTHTOK_ERR;
    size_t length = 0;
    if (!*password) {
        *password      = "\n";
        *cleanpassword = "\n";
        log_error("there is no password given");
        exit(PAM_AUTH_ERR);
    }
    length = (size_t)strlen(*password);
    if (!length){
        log_error("no password given");
        return PAM_AUTH_ERR;
    }

    if (token_length && *token_length > 0) {
        n = *token_length;
    }
    if (n > length) {
        log_error("password to short");
        return PAM_AUTH_ERR;
    }

    char *otp = malloc(length - n * sizeof(char));
    if(otp==NULL){
        log_error("Not enougth memory for OTP");
        return PAM_AUTH_ERR;
    }
    char *cleanpw = malloc(length * sizeof(char));
    if(cleanpw==NULL){
        free(otp);
        log_error("Not enougth memory for clean password");
        return PAM_AUTH_ERR;
    }
    if (length < n || n <= 0){
        log_debug("no tokenlength received, password will be cleaned from pam_sm_authenticate()");
    }
    log_debug("Token length = %i", n);

    strncpy(cleanpw, *password, (length - n) * sizeof(char));
    cleanpw[length - n] = '\0';
    strncpy(otp, *password + length - n, n);
    otp[n] = '\0';
    log_debug("OTP received: %s", otp);
    *cleanpassword = strdup(cleanpw);
    *password      = strdup(otp);
    ret = PAM_SUCCESS;

    log_debug("freeing data");
    /** Dont clean password, its used within the next PAM module
    erase_string(password);*/
    pam_set_data(pamh, "linotp_setcred_return", (void*) (intptr_t) &ret, NULL);
    erase_data(cleanpw, sizeof(cleanpw));
    erase_data(otp, sizeof(cleanpw));
    return ret;
}

int pam_linotp_get_pw_use_first_pass(
        pam_handle_t *pamh,
        char **password,
        char **cleanpassword,
        size_t *token_length,
        int use_first_pass)
{
    /** method to get the password from pam stack, mostly used for Apple computers
     * be careful: the use_first_pass option manipulates the pam stack,
     *             which is not allowed by most Linux systems.
     *
     * :param pamh: pam handle
     * :param password: reference to the password pointer
     * :param cleanpassword: reference to the cleaned password pointer
     * :param token_length: the expected token length
     * :param use_first_pass: to ensure
     * :return: int success / fail and in the password reference
     *          the catched password and cleaned password
     */

    if (!use_first_pass) {
        return PAM_AUTH_ERR;
    }

    /*
     * We do not ask for the password, but we get it from the PAM stack
     * use_first_pass is the only way it works for the MAC GUI
     */
    log_debug("Getting password from PAM stack using first pass");
    pam_get_item(pamh, PAM_AUTHTOK, (const void **)password);
    if (!password || !*password) {
#ifdef _OPENPAM
        log_debug("Error: password is null after get_item, lets try pam_get_authtok...");
        pam_get_authtok(pamh, PAM_AUTHTOK, (const char **)password, NULL);
#endif
        if (!password || !*password) {
            log_debug("Error: get_authtok failed");
            return PAM_AUTHTOK_ERR;
        }

        /* if password isnt received, we have to allocate the space */
        if (strlen(*password)) {
            *password    = malloc(sizeof(char));
            if(NULL==password){
                log_error("malloc password in pam_linotp_get_authtok failed");
                return PAM_AUTHTOK_ERR;
            }
            *password[0] = '\0';
        }
        log_debug("ok, password received");
    }
    return pam_linotp_extract_authtok(pamh, password, cleanpassword, token_length);
}

int pam_linotp_get_authtok_no_use_first_pass(
        pam_handle_t *pamh,
        char **password,
        char **cleanpassword,
        const char * prompt,
        size_t* token_length)
{
    /** method to get the password via challenge response mode
     *
     * :param pamh: pam handle
     * :param password: reference to the password pointer
     * :param cleanpassword: reference to the cleaned password pointer
     * :param prompt: what to show to the user
     * :param token_length: the expected token length
     *
     * :return: int success / fail and in the password reference
     *          the catched password and cleaned password
     */

    int ret = PAM_AUTHTOK_ERR;
    /* tokenlength is 0, if there was no configurated token_length,
     * so we cant ask for !(*token_length).
     */
    if(!(token_length)) {
        log_error("no token length given (pam_linotp_get_authtok)");
        return PAM_AUTH_ERR;
    } else {
        /* Using prompt to ask for password */
        log_debug("Using Prompt to get login data");
        if (!prompt){
            prompt = "Your OTP: ";
        }
        ret = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, (char **)password, "%s", prompt);
        if (!password || ret != PAM_SUCCESS){
            log_debug("cant get password");
            return PAM_AUTHTOK_ERR;
        }
        log_debug("OTP received successfully %s", *password);
        *token_length = (size_t)strlen(*password);
        return ret;
    }
}

int pam_linotp_get_authtok(pam_handle_t *pamh, char **password, char **cleanpassword,
        const char * prompt, int use_first_pass, size_t* token_length)
{
    /** method to get the password from the pam console
     * which hides the use_fist_pass / challange respone differences
     *
     * :param pamh: pam handle
     * :param password: reference to the password pointer
     * :param cleanpassword: reference to the cleaned password pointer
     * :param prompt: what to show to the user
     * :param use_first_pass: special case for the apple password catch
     *
     * :return: int success / fail and in the password reference
     *          the catched password and cleaned password
     */

    int ret = PAM_AUTHTOK_ERR;
    if(use_first_pass){
        ret = pam_linotp_get_pw_use_first_pass(
            pamh,
            password,
            cleanpassword,
            token_length,
            use_first_pass);
    } else {
        ret = pam_linotp_get_authtok_no_use_first_pass(
            pamh,
            password,
            cleanpassword,
            prompt,
            token_length);
    }
    return ret;
}

/*****************************************************************************
 * linotp PAM callbacks and module definitions
*****************************************************************************/
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char *argv[]) {

    /**
     *  pam authentication callback, its called from PAM to authenticate
     *  the user with a one time password
     *
     *  :param *pamh: handler to the pam context
     *  :param flags: PAM_SILENT - defines the debug message behavior
     *                PAM_DISALLOW_NULL_AUTHTOK - will be ignored,
                      because it doesn't matter for OTP Athentications
     *  :param argc: counter of the provided arguments
     *  :param argv: pointer to the array of arguments
     */
    int debugflag_pam = 0;
    if(flags && PAM_SILENT == flags){
            debugflag_pam = 1;
    }
    log_info("Authentication stated...");

    LinOTPConfig config;
    char *user          = NULL;
    char *password      = NULL;
    char *cleanpassword = NULL;
    int   ret = PAM_AUTH_ERR;

    ret = pam_linotp_get_config(argc, argv, &config, debugflag_pam);
    if (ret != PAM_SUCCESS) {
        log_error("Failed to read the linOTP pam config");
        return ret;
    }
    if (!config.url) {
        log_error("Invalid linOTP pam configuration (url missing)");
        return PAM_AUTH_ERR;
    }

    /* identify user */
    /* for later usage - we can set / localize as well the Login prompt
     *     pam_set_item(pamh, PAM_USER_PROMPT, "Login: ");
     */
    if ((ret = pam_get_user(pamh, (const char**)&user, NULL)) != PAM_SUCCESS) {
        log_error("Failed to read the username");
        return ret;
    }
    if (!user) {
        log_error("Invalid Username, username cannot be null");
        return PAM_AUTH_ERR;
    }

    /** Now get the password, it will try all configured token length values,
     *  if tokenlength == 0, we have to ask the Appliance for it
     */
    // Check otp/password...
    int_array tok = get_possibtok(config.tokenlength);
    log_info("<token-lengths length='%i'>", tok.length);
    unsigned int x;
    for (x = 0; x < tok.length; x++)
        log_debug("  length[%i]=%i", x, tok.buff[x]);
    log_info("</token-lengths>");

    unsigned int i;
    for (i = 0; i < tok.length; i++) {
        log_debug("Getting password");
        size_t token_len = tok.buff[i];
        ret = pam_linotp_get_authtok(pamh, &password, &cleanpassword, config.prompt, config.use_first_pass, &token_len);
        log_debug("End of password fetching.");

        /* validate password */
        if (PAM_SUCCESS==ret) {
            //ASSERT(password      != NULL);
            //ASSERT(cleanpassword != NULL);
            if (password) {  // <- valid auth information
                /** we got the password, so we will check it against LinOTP **/
                ret = pam_linotp_validate_password(pamh, user, password, &config);
                log_info("pam_linotp_validate callback done. [%i]", ret);

                if (cleanpassword && *cleanpassword) {
                    /* Set the clean PW for the next PAM module */
                    log_debug("set the password for next pam module");

                    char *pw2stack = strdup(cleanpassword);
                    if(!pw2stack || !*pw2stack){
                        log_debug("pw2stack was empty");
                        break;
                    }
                    if (pam_set_item(pamh, PAM_AUTHTOK, pw2stack) == PAM_SUCCESS) {
                        // Login successful, remove password and exit for!
                        erase_string(password);
                        erase_string(cleanpassword);
                        if (PAM_SUCCESS == ret) {
                            log_info("pam_sm_authenticate: success!");
                        }
                        break;
                    }

                    // Ups, we were unable to store password. Remove buffer and try next :-(
                    erase_string(pw2stack);
                    log_error("Login canceled, cant update password");

                }
                erase_string(cleanpassword);
                erase_string(password);
            } else {
                ret = PAM_AUTH_ERR;
                log_debug("password was null");
            }
        }
    }
    if (tok.buff != NULL) {
        erase_data(tok.buff, tok.length);
    }
    if (config.prompt != NULL) {
        erase_string(config.prompt);
    }
    /* Dont clean pw2stack, its used within the next PAM module. */
    if (PAM_SUCCESS!=ret) {
        log_info("pam_linotp callback done. [%s]", pam_strerror (pamh, ret));
        log_debug("PAM failed");
    }
    return ret;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh, int flags, int argc,
        const char **argv) {
    return PAM_SUCCESS;
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_linotp");
#endif

#ifdef PAM_STATIC
struct pam_module _pam_linotp_modstruct = {
    "pam_linotp",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL
};
#endif
