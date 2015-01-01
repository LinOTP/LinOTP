/*
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2015 LSE Leading Security Experts GmbH
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

auth    [success=1 default=ignore] 	pam_linotp.so noosslhostnameverify \
			nosslcertverify url=http://linotpserver/validate/simplecheck \
			realm=mydefrealm
 *
 * parmeters are here:
 *
 *  pam_linotp.so 			- the module ref, which should be in /lib/security
 *                            in most cases
 *  url=http://l...			- the reference to your linotp server
 *  realm=..				- the default realm, where the user is to be searched
 *  noosslhostnameverify 	- when using ssl, switch the ssl host verification off
 *  nosslcertverify			- when using ssl, switch the ssl cert verification off
 *
 *  debug 					- use this with care as this will display critical
 *  						  data in the log files
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


#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <syslog.h> 

#include	<curl/curl.h>

#define PAM_LINO_CHALLENGE 	99
#define LINOTPD_OK			":-)"
#define LINOTPD_REJECT		":-("
#define LINOTPD_FAIL		":-/"

#define MAXMEMSIZE 		1024 * 1024

/* config enries maxlen */
#define URLMAXLEN	1000
#define REALMMAXLEN	100
#define RESMAXLEN	100


/*****************************************************************************/

static char password_prompt[] = "Your OTP:";

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

} LinOTPConfig ;

int pam_linotp_get_authtok(pam_handle_t *pamh, char **password,
		char * prompt, int use_first_pass);

int pam_local_get_authtok(pam_handle_t *pamh, int item, char **password,
		char * prompt, int use_first_pass);

int pam_linotp_validate_password(pam_handle_t *pamh,
		char *user, char *password,
		LinOTPConfig *config);

/************** syslog stuff **********************/

static void do_log(int type, char * format, ...) {

	va_list args;
	va_start(args, format);
	openlog("pam_linotp", LOG_PID, LOG_AUTHPRIV);
	vsyslog(type, format, args);
	closelog();
	va_end(args);

}
#define log_error(format, ...)   do_log(LOG_ERR,     "ERROR: "   #format, ## __VA_ARGS__)
#define log_debug(format, ...)   do_log(LOG_DEBUG,   "DEBUG: "   #format, ## __VA_ARGS__)
#define log_warning(format, ...) do_log(LOG_WARNING, "WARNING: " #format, ## __VA_ARGS__)
#define log_info(format, ...)    do_log(LOG_INFO,    "INFO: "    #format, ## __VA_ARGS__)

/* protect memset from compiler optimization  */
void *memset_s(void *v, int c, size_t n) {
  volatile unsigned char *p = v;
  while (n--)
    *p++ = c;
 
  return v;
}

char * erase_data(void * data, int len) {
	/* wipe all data and free the memory */
	memset_s(data, 0, len);
	free(data);
	return NULL;
}
char * erase_string(char * string) {
	/* wipe all data and free the memory */
	if (string!= NULL)
		memset_s(string, 0, strlen(string));
	free(string);
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
	size_t realsize = size * nmemb;


	/*Check for Max_size*/
	if (realsize > MAXMEMSIZE) {
		log_error(
				"ERROR: The linotpd responded to our authentication "\
				"request with more than 1MB of data! Something is really "\
				"wrong here!");

		return mem->size;
	}
	/* do the alloc or realloc*/
	char * tmp;
	if (mem->memory == NULL) {
		tmp = malloc(mem->size + realsize + 1);
	}
	else {
		tmp = realloc(mem->memory, mem->size + realsize + 1);
	}
	if (tmp == NULL) {
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
	if (strlen(LINOTPD_REJECT) >= strlen(s)) return;

	fin = strchr(s+strlen(LINOTPD_REJECT), ' ');
	if (fin == NULL) return;

	/*now search start of stat */
	while(*fin != '\0')
	{
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
char * linotp_create_url_params(CURL *curl_handle,int number_of_pairs, ...)
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
	int     i = 0;
	int  size = 0;

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

	/* concat the values in the param string*/
	for (i= 0; i< number_of_pairs; i++){

		if (arry[i][0] != NULL && arry[i][1] != NULL) {
			if (i>0) strcat(param,"&");
			strcat(param, arry[i][0]);
			strcat(param, "=");
			strcat(param, arry[i][1]);

			/* finally clean up the escaped data*/
			log_debug("freeing escaped value for %s", arry[i][0]);

			/* memset the data before - so no pass etc. will be in memory */
			memset(arry[i][0],0, strlen(arry[i][0]));
			curl_free(arry[i][0]);

			memset(arry[i][1],0, strlen(arry[i][1]));
			curl_free(arry[i][1]);
		}
	}


	return param;
}


int linotp_send_request(CURL *curl_handle, char * url, char * params,
		struct MemoryStruct * chunk,
		int nosslhostnameverify, int nosslcertverify) {
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
	int all_status = 0;
	int status = 0;

	/* Setup the base url */
	status = curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	all_status += status;

	/* Now specify the POST data */
	status = curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, params);
 	all_status += status;

	status = curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION,
			curl_write_memory_callback);
	all_status += status;

	status = curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, chunk);
	all_status += status;

	status = curl_easy_setopt(curl_handle, CURLOPT_USERAGENT,
			"libcurl-pam-agent/1.0");
	all_status += status;

	if (nosslhostnameverify)
		status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
	else
		status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 2L);
	all_status += status;

	if (nosslcertverify)
		status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
	else
		status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);
	all_status += status;

	status = curl_easy_perform(curl_handle);
	all_status += status;

	curl_easy_cleanup(curl_handle);

	return all_status;

}
/********** LinOTP stuff ***************************/
int linotp_auth(char *user, char *password,
		LinOTPConfig *config, char ** state, char ** challenge ) {
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
	chunk.memory = NULL; 		/* we expect realloc(NULL, size) to work */
	chunk.size = 0; 			/* no data at this point */

	curl_global_init(CURL_GLOBAL_ALL);

	curl_handle = curl_easy_init();

	if (curl_handle == NULL ) {
		log_error("could not get curl_handle!");
		returnValue = PAM_AUTH_ERR;
		goto cleanup;
	}

	curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, errorBuffer);

	param = linotp_create_url_params(curl_handle, 5,
			"realm", config->realm,
			"resConf", config->resConf,
			"user", user,
			"pass", password,
			"state", *state);

	if (param == NULL) {
		log_error("could allocate size for url");
		goto cleanup;
	}

	if (config->debug) {
		log_debug("connecting to url:%s with parameters %s", config->url, param);
	}

	all_status = linotp_send_request(curl_handle, config->url, param, (void *) &chunk,
			config->nosslhostnameverify, config->nosslcertverify);

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

		//log_debug("Challenge response:'%s'", chunk.memory);
		linotp_split_stat_and_message(chunk.memory,&stat,&msg);

		/* we have to create duplicates, as they start as pointers into the
		 * chunk memory, which will be freed at the end of this function
		 * */
		log_info("Challenge authentication:'%.8s...' '%.8s...'",
														*challenge, *state);
		/* msg and stat are never NULL*/
		*challenge = strdup(msg);
		*state = strdup(stat);
		if ((*challenge == NULL) || (*stat == NULL)) {
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
	{
		log_error("An error occured for '%s' on '%s'\n %.10s\n", user,
				config->url,chunk.memory);
		returnValue = PAM_AUTH_ERR;
		goto cleanup;
	}

	cleanup:

	chunk.memory = erase_data(chunk.memory, chunk.size);
	chunk.size = 0;

	param = erase_string(param);

	/* we're done with libcurl, so clean it up */
	curl_global_cleanup();

	return (returnValue);
}

int pam_linotp_get_config(int argc, const char *argv[], LinOTPConfig * config) {
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


	int i = 0;

	for ( i = 0; i < argc; i++ ) {
		if (strcmp(argv[i], "debug") == 0)
			config->debug = 1;
	}

	for ( i = 0; i < argc; i++ ) {
		if (strcmp(argv[i], "nosslhostnameverify") == 0) {
			config->nosslhostnameverify = 1;
		} else if (strcmp(argv[i], "nosslcertverify") == 0) {
			config->nosslcertverify = 1;
		} else if (strcmp(argv[i], "debug") == 0) {
			config->debug = 1;
		} else if (strcmp(argv[i], "use_first_pass") == 0) {
			config->use_first_pass = 1;
		}
		/* check for validate url */
		else if (strncmp(argv[i], "url=", strlen("url=")) == 0) {
			// this is the validateurl
			if (strlen(argv[i]) > URLMAXLEN) {
				log_error("Your url is to long: %s (max %d)", argv[i],
						URLMAXLEN);
				return (PAM_AUTH_ERR);
			} else {
				config->url = (char*) argv[i] + strlen("url=");
			}

		}
		/* check for realm */
		else if (strncmp(argv[i], "realm=",strlen("realm=")) == 0) {
			if (strlen(argv[i]) > REALMMAXLEN) {
				log_error("Your realmname is to long: %s (max %d)", argv[i],
						REALMMAXLEN);
				return (PAM_AUTH_ERR);
			} else {
				config->realm = (char*) argv[i] + strlen("realm=");
			}
		}
		/* check for resolver */
		else if (strncmp(argv[i], "resConf=", strlen("resConf=")) == 0) {
			if (strlen(argv[i]) > RESMAXLEN) {
				log_error("Your resolver config name is to long: %s", argv[i]);
				return (PAM_AUTH_ERR);
			} else {
				config->resConf = (char*) argv[i] + strlen("resConf=");
			}
		}
		/* check for prompt */
		else if (strncmp(argv[i], "prompt=", strlen("prompt=")) == 0) {
			if (strlen(argv[i]) > RESMAXLEN) {
				log_error("Your prompt definition is to long: %s [%]", argv[i], RESMAXLEN);
				return (PAM_AUTH_ERR);
			} else {
				config->prompt = (char*) argv[i] + strlen("prompt=");
			}
		}

	}
	if (config->debug) {
		log_debug("realm: %s", config->realm);
		log_debug("resConf: %s", config->resConf);
		log_debug("validate url: %s", config->url);
		log_debug("prompt: %s", config->prompt);

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
{	/**
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

	char * state = NULL;
	char * challenge  = NULL;

	int ret = linotp_auth(user, password, config, &state, &challenge);
	if (ret != PAM_LINO_CHALLENGE){
		return ret;
	}

	/**
	 * we are in challenge mode: ask for a response to the challenge
	 **/
	log_debug("we are in challenge mode: %d", ret);

	if (config->debug)
		log_debug("challenge >%.10s< >%.10s< ", challenge, state);

	char * response = NULL;
	ret = pam_linotp_get_authtok(pamh, &response, challenge, 0);

	/* now the challenge is done, we can clean the dishes
	 * :: challenge is not more required, but state is used as
	 *    input to reference the transaction */
	if (config->debug)
		log_debug("free challenge: %.10s" , challenge);

	challenge = erase_string(challenge);

	if (config->debug)
		log_debug("submitting challenge response: %s ", response);

	ret = linotp_auth(user, response, config, &state, &challenge);

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

int pam_linotp_get_authtok(pam_handle_t *pamh, char **password,
		char * prompt, int use_first_pass)
{
	/** method to get the password from the pam console
	 * which hides the openpam / not openpam differences
	 *
	 * :param pamh: pam handle
	 * :param item: return type, which is meant to be PAM_AUTHTOK
	 * :param password: reference to the password pointer
	 * :param prompt: what to show to the user
	 * :param use_first: special case for the apple password catch
	 *
	 * :return: int success / fail and in the password reference the catched password
	 */

	int ret = PAM_SUCCESS;

	#ifdef _OPENPAM
		log_debug("Using OPENPAM");
		ret = pam_get_authtok(pamh, PAM_AUTHTOK, (const void **)password, prompt);
	#else
		log_debug("Not using OPENPAM.");
		ret = pam_local_get_authtok(pamh, PAM_AUTHTOK, password, prompt, 0);
	#endif

	return ret;
}

int
pam_local_get_authtok(pam_handle_t *pamh, int item, char **password,
		char * prompt, int use_first_pass) {
	/* this method tries to be similar to the openPam interface
	 *
	 * 	pam_get_authtok(pamh, PAM_AUTHTOK, (const void **)&password, challenge);
	 *
	 * 	so that we only have to create a simple wrapper: get_authtok()
	 *
	 * :param pamh: pam handle
	 * :param item: return type, which is meant to be PAM_AUTHTOK
	 * :param password: reference to the password pointer
	 * :param prompt: what to show to the user
	 * :param use_first: special case for the apple password catch
	 *
	 * :return: int success / fail and in the password reference the catched password
	 */

	int ret = PAM_SUCCESS;

	log_debug("pam_local_get_authtok");

	const struct pam_conv *conv;
	struct pam_message msg;
	struct pam_response *resp = NULL;

	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = prompt;

	struct pam_message * msgp = &msg;

	ret = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
	if (ret != PAM_SUCCESS) {
		log_error("Failed to do pam_get_item");
		ret = PAM_SYSTEM_ERR;
		return ret;
	}

	if (1 == use_first_pass) {
		/*
		 * We do not ask for the password, but we get it ftom the PAM stack
		 * use_first_pass is the only way it works for the MAC GUI
		 */
		ret  = pam_get_item(pamh, item, (const void **) &password);
		log_debug("Getting password from PAM stack. result: %d", ret);
	} else {
		/*
		 * No use_first_pass, we have to do the conversation to get the password.
		 * FIXME: The conversation does not work with the MAC GUI!
		 */
		log_debug("pam_local_get_authtok");
		ret = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);
		log_debug("Getting password from PAM conversation. result: %d", ret);

		if (resp != NULL ) {
			log_debug("response code: %s ", resp->resp_retcode);
			if (ret == PAM_SUCCESS) {
				if ((char *) resp->resp != NULL) {
					/* take care - strdup might fail*/
					*password = strdup((char *) resp->resp);
					if (*password == NULL)
						ret = PAM_SYSTEM_ERR;
				} else {
					log_warning("null password retrieved!");
					/* take care - strdup might fail*/
					*password = strdup("");
					if (*password == NULL)
						ret = PAM_SYSTEM_ERR;
				}
			}
		} else {
			log_debug("response of PAM conversation is null!");
		}
	}

	if (resp != NULL)
		erase_string(resp->resp);
	free(resp);

	return ret;
}

/*****************************************************************************
 * linotp PAM callbacks and module definitions
*****************************************************************************/
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char *argv[]) {
	/**
	 *  pam authentication callback
	 *
	 *  :param *pamh: handler to the pam context
	 *  :param flags: ??
	 *  :param argc: counter of the provided arguments
	 *  :param argv: pointer to the array of arguments
	 */

	LinOTPConfig config;
	struct passwd *pwd = NULL;
	char *user = NULL;
	char *password = NULL;

	/* last resort */
	int ret = PAM_AUTH_ERR;

	ret = pam_linotp_get_config(argc, argv, &config);
	if (ret != PAM_SUCCESS) {
		log_error("Failed to read the linOTP pam config");
		return (ret);
	}

	/* identify user */
	/* for later usage - we can set / localize as well the Login prompt
	 * 	pam_set_item(pamh, PAM_USER_PROMPT, "Login: ");
	 */
	if ((ret = pam_get_user(pamh, (const char**)&user, NULL )) != PAM_SUCCESS) {
		return (ret);
	}

	/* we do not check if user exists in the system
	  log_debug("got user %s", user);
	  if ((pwd = getpwnam(user)) == NULL ) {
		  return (PAM_USER_UNKNOWN);
	  }
    */
	/** Now get and the password */
	log_debug("Getting password");
	ret = pam_linotp_get_authtok(pamh, &password, config.prompt, config.use_first_pass);
	if (ret == PAM_AUTH_ERR)
		log_error("failed to pam_get_authtok: %d.", ret);

	log_debug("End of password fetching.");
	if (ret != PAM_SUCCESS) {
		log_error("pam_err: %d", ret);
		ret = PAM_AUTH_ERR;
		goto cleanup;
	}
	if (ret == PAM_CONV_ERR) {
		log_error("Failed to get authtoken. PAM_CONV_ERR occurred: %d",ret);
		goto cleanup;
	}

	/** if we got the password, we will check this against LinOTP **/
	if (ret == PAM_SUCCESS) {
		if (config.debug)
			log_debug("Ok, you are debugging - here your pass: %s", password);

		/* validate password */
		if (user != NULL && password != NULL && config.url != NULL ) {
			ret = pam_linotp_validate_password(pamh, user, password, &config);
		} else {
			log_error("The username, the password or the validateurl were NULL!");
			ret = PAM_AUTH_ERR;
		}
	} else
		ret = PAM_AUTH_ERR;


cleanup:
	log_debug("freeing password");
	erase_string(password);

	pam_set_data(pamh, "linotp_setcred_return", (void*) (intptr_t) &ret, NULL);
	log_info("pam_linotp callback done. [%s]", pam_strerror (pamh, ret));

	return (ret);
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
