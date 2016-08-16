/*
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
 *
 *   This file is part of LinOTP authentication modules.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.

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


#include	<stdbool.h>
#include	<stdlib.h>
#include	<string.h>
#include	<stdio.h>
#include	<ctype.h>

#include	<freeradius-devel/libradius.h>

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>
#include	<freeradius-devel/sysutmp.h>
#include	<freeradius-devel/conffile.h>

#include	<curl/curl.h>


/*
 * debug macros
 */
#define log(level, format, ...) \
	radlog(level, "rlm_linotp: " format, ## __VA_ARGS__)

#define log_info(format, ...) \
	log(L_INFO, format, ## __VA_ARGS__)
	
#define log_error(format, ...) \
	log(L_ERR, format, ## __VA_ARGS__)	

#define log_debug(format, ...) \
	log(L_DBG, "(%s) " format, __FUNCTION__, ## __VA_ARGS__)



// libltdl is so buggy...add this in radius.h

#define lt__PROGRAM__LTX_preloaded_symbols lt_libltdl_LTX_preloaded_symbols

// username and password was correct
#define LINOTPD_OK			":-)"
#define LINOTPD_REJECT			":-("
#define LINOTPD_FAIL			":-/"



/*****************************************************************************/

typedef struct LOTPInstance { 
	char *validateurl;
	int sslcertverify;
	int sslhostnameverify;
	char *realm;
	char *resConf;
	int loguser;
	int logpassword;
	int restrictusername;
	int allowemptypassword;
	int prefer_nas_identifier;
} lotp_inst_t;


struct MemoryStruct {
  char *memory;
  size_t size;
};


/*****************************************************************************/

char *createUrl4Post(CURL *curl_handle,
		     const char *realm,
		     const char *resConf,
		     const char *user,
		     const char *password,
		     const char *client,
		     const char *state);


char *sendRequest(lotp_inst_t *lotp,
		  CURL *curl_handle,
		  const char *params);


bool split_stat_and_msg(const char *str, char **stat, char **msg);



/*****************************************************************************/

/* A mapping of configuration file names to internal variables. */
static const CONF_PARSER module_config[] =
{
	{ "validateurl", 		PW_TYPE_STRING_PTR,
							offsetof(lotp_inst_t, validateurl), 		NULL, NULL },
	{ "sslhostnameverify",  PW_TYPE_BOOLEAN,
							offsetof(lotp_inst_t, sslhostnameverify), 	NULL, "yes" },
	{ "sslcertverify",    	PW_TYPE_BOOLEAN,
							offsetof(lotp_inst_t, sslcertverify), 		NULL, "yes" },
	{ "realm",	 		PW_TYPE_STRING_PTR,
							offsetof(lotp_inst_t, realm), 		NULL, NULL },
	{ "resConf",	 	PW_TYPE_STRING_PTR,
							offsetof(lotp_inst_t, resConf), 	NULL, NULL },
	{ "loguser",		PW_TYPE_BOOLEAN,	
							offsetof(lotp_inst_t, loguser),		NULL, "yes" },
	{ "logpassword",	PW_TYPE_BOOLEAN,
							offsetof(lotp_inst_t, logpassword),	NULL, "no" },
	{ "restrictusername",	PW_TYPE_BOOLEAN,
							offsetof(lotp_inst_t, restrictusername),	NULL, "yes" },
	{ "allowemptypassword",	PW_TYPE_BOOLEAN,
							offsetof(lotp_inst_t, allowemptypassword),	NULL, "no" },
	{ "prefer_nas_identifier",	PW_TYPE_BOOLEAN,
							offsetof(lotp_inst_t, prefer_nas_identifier),	NULL, "no" },
	{ NULL, -1, 0, NULL, NULL }
};

/*****************************************************************************/

static int lotp_instantiate(CONF_SECTION *conf, void **instancep)
{
	lotp_inst_t *lotp;
//	unsigned char encparam[32];
//	size_t encparamsz = sizeof(encparam);
	
	lotp = rad_malloc(sizeof(*lotp));
	if (!lotp)
	{
		return -1;
	}

	memset(lotp, 0, sizeof(*lotp));

	if (cf_section_parse(conf, lotp, module_config) < 0)
	{
		free(lotp);
		return -1;
	}

	/* Check required options */
	if (!lotp->validateurl)
	{
		log_error("options are incomplete");
		free(lotp);
		return -1;
	}

	/* initialize CURL */
	curl_global_init(CURL_GLOBAL_ALL);


	*instancep = lotp;
	return 0;
}

static int lotp_detach(void *instance)
{
	if (instance == NULL)
		return 0;

	/* shutdown CURL */
	curl_global_cleanup();

	/* free our context data */
	memset(instance, 0, sizeof(lotp_inst_t));
	free(instance);

	return 0;
}

/*****************************************************************************/

static int lotp_acct(void *instance, REQUEST *request)
{
	(void)instance;		/* unused */
	(void)request;		/* unused */
	return RLM_MODULE_NOOP;
}

/*****************************************************************************/

static inline int valid_char(unsigned char c)
{
	/* a-z A-Z 0-9*/
	if (isalnum(c))
		return 1;

	/* Non-alphanumeric: we disallow anything except known good */
	switch (c) {
	case '-':
	case '_':
	case '+':
	case '.':
	case '@':
		return 1;
	}
	
	/* Invalid */
	return 0;
}

static inline int valid_realm_char(unsigned char c)
{
	/* a-z A-Z 0-9*/
	if (isalnum(c))
		return 1;

	/* Non-alphanumeric: we disallow anything except known good */
	switch (c) {
	case '-':
	case '_':
		return 1;
	}

	/* Invalid */
	return 0;
}


#ifndef LINOTP_MAX_USERNAME_LEN
#define LINOTP_MAX_USERNAME_LEN 256
#endif

#ifndef LINOTP_MAX_REALMNAME_LEN
#define LINOTP_MAX_REALMNAME_LEN 256
#endif


static inline int valid_username(const char *name)
{
	const char *s = name;

	while (*s)
	{
		if (!valid_char(*s))
			return 0;

		if ((s-name) >= LINOTP_MAX_USERNAME_LEN)
			return 0;

		++s;
	}

	return 1;
}

static inline int valid_realm(const char *realm)
{
	const char *s = realm;

	if (*s == '\0')
	{
		return 1;
	}
	while (*s)
	{
		if (!valid_realm_char(*s))
			return 0;
		if ((s-realm) >= LINOTP_MAX_REALMNAME_LEN)
			return 0;
		++s;
	}
	return 1;
}

/***********************************************
   Curl stuff
***********************************************/

/* don't accept more than CURL_RECV_LIMIT per callback-event from CURL.
 * this also limits the maximum amount of data we can receive from LinOTP
 * to 2*CURL_RECV_LIMIT.
 */
#define CURL_RECV_LIMIT		(1024*1024)

static size_t WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *data)
{
	struct MemoryStruct *mem = (struct MemoryStruct *)data;
	size_t realsize;

	/* limit size and nmemb by square root of maximum capacity of size_t */
	if ((size >> (4*sizeof(size_t))) || (nmemb >> (4*sizeof(size_t)))) {
		log_error("Possible integer overflow in WriteMemoryCallback detected");
		return 0;
	}
	realsize = size * nmemb;

	/* we actually allow much less than our 'overflow check' above does */
	if (realsize > CURL_RECV_LIMIT || mem->size > CURL_RECV_LIMIT)
	{
		log_error("The linotpd responded to our authentication request with more than 1MB of data! Something is really wrong here!");
		return 0;
	}

	/* mem->size will be at most 2*CURL_RECV_LIMIT+1 */

	if (mem->memory == NULL)
		mem->memory = malloc(realsize + 1);
	else
		mem->memory = realloc(mem->memory, mem->size + realsize);

	if (mem->memory == NULL)
		return 0;

	memcpy(mem->memory + mem->size, ptr, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = '\0';

	return realsize;
}


char *createUrl4Post(CURL *curl_handle,
		     const char *realm,
		     const char *resConf,
		     const char *user,
		     const char *password,
		     const char *client,
		     const char *state)
{
	/*
	doing a post request requires for curl to have all the parameters
	concatenated into one string, where the parameters are seperated
	by & and the key/value by the '=' sign

		realm=myrealm&user=me

	if a parameter value is NULL or has no length, it won't be appended
	
	currently there are six parameters - if extended adjust the argc

	all parameter values are first url escaped and will be freed after
	the concatenation.
	*/
	int     i = 0;
	int  size = 0;

	int argc = 6;
	const char *key_name[argc];
	char *key_value[argc];

	/* the return value */
	char *param = NULL;


	log_debug("entering createUrl4Post.");
	/*** initialize array****/
	for (i= 0; i < argc; i++)
	{
		key_name[i] = NULL;
		key_value[i] = NULL;
	}
	i = 0;
	if ( realm != NULL )
	{
		key_name[i] = "realm";
		key_value[i] = curl_easy_escape(curl_handle, realm, 0);
		i++;
	}
	if ( resConf != NULL )
	{
		key_name[i] = "resConf";
		key_value[i] = curl_easy_escape(curl_handle, resConf, 0);
		i++;
	}
	if ( user != NULL )
	{
		key_name[i] = "user";
		key_value[i] = curl_easy_escape(curl_handle, user, 0);
		i++;
	}
	if ( password != NULL )
	{
		key_name[i] = "pass";
		key_value[i] = curl_easy_escape(curl_handle, password, 0);
		i++;
	}
	if ( client != NULL )
	{
		key_name[i] = "client";
		key_value[i] = curl_easy_escape(curl_handle, client, 0);
		i++;
	}
	if ( state != NULL )
	{
		key_name[i] = "state";
		key_value[i] = curl_easy_escape(curl_handle,state, 0);
		i++;
	}

	/* now we calculate the required size of the param str*/
	int length = 0;
	for (i = 0; i < argc; i++)
	{
		if (key_name[i] != NULL) 
		{
			log_debug("[%d] %s=%s\n", i, key_name[i], key_value[i]);
			length += strlen(key_name[i]) + 1; /* add 1 for '&'*/
			length += strlen(key_value[i]) + 1; /* add 1 for '='*/
		}
	}

	size = length + 1;
	log_debug("allocating %d chars", size);
	param = calloc(size, sizeof(char));
	if (param == NULL) {
		for (i = 0; i < argc; i++)
			if (key_value[i] != NULL)
				curl_free(key_value[i]);
		return NULL;
	}

	/* concat the values in the param string*/
	*param = '\0';
	for (i= 0; i< argc; i++){
		if (key_name[i] != NULL && key_value[i] != NULL) {
			if (i>0) strcat(param,"&");
			strcat(param, key_name[i]);
			strcat(param, "=");
			strcat(param, key_value[i]);

			/* finally clean up the escaped data*/
			log_debug("freeing escaped value for %s", key_value[i]);
			curl_free(key_value[i]);
		}
	}

	return param;
}

char *sendRequest(lotp_inst_t *lotp,
		  CURL *curl_handle,
		  const char *params)
{
	struct MemoryStruct chunk = { NULL, 0 };
	CURLcode status;

	/* Setup the base url */
 	status = curl_easy_setopt(curl_handle, CURLOPT_URL, lotp->validateurl);
 	if (status != CURLE_OK)
 	{
		if ( lotp->logpassword && lotp->loguser )
			log_error("Error setting option CURLOPT_URL %s: %i", params, status);
		else
			log_error("Error setting option CURLOPT_URL %s: %i", lotp->validateurl, status);
		return NULL;
 	}

	/* Now specify the POST data */ 
	status = curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, params);
 	if (status != CURLE_OK)
 	{
		if ( lotp->logpassword && lotp->loguser )
			log_error("Error setting option CURLOPT_POSTFIELDS %s: %i", params, status);
		else
			log_error("Error setting option CURLOPT_POSTFIELDS %s: %i", lotp->validateurl, status);
		return NULL;
 	}

 	status 	= curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
 	if (status != CURLE_OK) {
		log_error("Error setting option CURLOPT_WRITEFUNCTION: %i", status);
		return NULL;
 	}

 	status 	= curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &chunk);
 	if (status != CURLE_OK) {
		log_error("Error setting option CURLOPT_WRITEDATA: %i", status);
		return NULL;
 	}

	status = curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1L);
	if (status != CURLE_OK) {
		log_error("Error setting option CURLOPT_NOSIGNAL: %i", status);
		return NULL;
	}

	status = curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
	if (status != CURLE_OK) {
		log_error("Error setting option CURLOPT_USERAGENT: %i", status);
		/* XXX ignore this error? */
	}

 	if ( lotp->sslhostnameverify )
		status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 2L);
	else
		status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);

	if (status != CURLE_OK) {
		log_error("Error setting option CURLOPT_SSL_VERIFYHOST: %i", status);
		return NULL;
	}

 	if (lotp->sslcertverify)
 		status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);
	else
 		status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);

 	if (status != CURLE_OK) {
		log_error("Error setting option CURLOPT_SSL_VERIFYPEER: %i", status);
		return NULL;
 	}

 	status = curl_easy_perform(curl_handle);
 	if (status != CURLE_OK) {
		log_error("Error in curl_easy_perform: %i, url: %s", status, lotp->validateurl);

		return NULL;
	}

	return chunk.memory;
}


/* split_stat_and_msg - extracts stat and message from LinOTP reject
 *
 * Input:
 *   str is expected to point right after the sad smily of a reject message.
 *   stat and msg must point to legal string-pointers for storing the result.
 *
 * Return:
 *   True if everything is ok; *stat and *msg hold pointers to the expected
 *   strings and must be freed after use.
 *
 *   False in case of error; stat and msg are undefined
 */

bool
split_stat_and_msg(const char *str, char **stat, char **msg)
{
	const char *a, *b;

	/* the first character after smiley must be an space */
	if (*str != ' ')
		return false;

	/* find a and b such that [a, b) is the first word in str without spaces */
	for (a = str+1; *a == ' '; a++);
	for (b = a; *b != '\0' && *b != ' '; b++);
	*stat = strndup(a, b-a);
	if (*stat == NULL)
		return false;

	/* find first non-space after b and take everything from there as msg */
	while (*b == ' ') b++;
	*msg = strdup(b);
	if (*msg == NULL) {
		free(*stat);
		return false;
	}

	return true;
}




/********** LinOTP stuff ***************************/

static int lotp_auth(void *instance, REQUEST *request)
{
	VALUE_PAIR *state_pair;
	char *state = NULL;
	VALUE_PAIR *reply;

	char errorBuffer[CURL_ERROR_SIZE];
	CURL *curl_handle = NULL;

	lotp_inst_t *lotp = instance;
	int prefer_nas_identifier = (lotp->prefer_nas_identifier);

	int returnValue	= RLM_MODULE_FAIL;
	char *params = NULL;
	char *answer = NULL;
	
	/* maybe we can use this (the definition from clients.conf) one day */
	//char * shortname	= request->client->shortname;

	/*
	 * find the client ip or use the nas ip if it is prefered and available
	 */
	const char *client_ip;
	log_info("getting client ip now.");

	/* check for the nas ip */
	log_debug("prefer_nas_identifier %d", prefer_nas_identifier);

	VALUE_PAIR *vp = NULL;
	char buffer[INET6_ADDRSTRLEN];
	if (prefer_nas_identifier && 
	    (vp = pairfind(request->packet->vps, PW_NAS_IP_ADDRESS)) != NULL) {
		log_debug("using NAS_IP_ADDRESS");
		client_ip = inet_ntop(AF_INET,
					&(vp->vp_ipaddr),        /* src  */
					buffer, sizeof(buffer)); /* dest */
	} else if (prefer_nas_identifier &&
                   (vp = pairfind(request->packet->vps, PW_NAS_IPV6_ADDRESS)) != NULL) {
		log_debug("using NAS_IPV6_ADDRESS");
		client_ip = inet_ntop(AF_INET6,
					&(vp->vp_ipv6addr),      /* src  */
					buffer, sizeof(buffer)); /* dest */
	} else {
		/* or as fallback the request client ip (can be of type IPv4 or IPv6) */
		log_debug("using CLIENT_IP_ADDRESS");
		client_ip = inet_ntop(request->packet->src_ipaddr.af,
					&(request->packet->src_ipaddr.ipaddr), /* src  */
					buffer, sizeof(buffer));	       /* dest */
	}
	log_info("got client ip: %s.", (client_ip != NULL ? client_ip : ""));


	if (!request)
	{
		log_error("No Request!");
		returnValue = RLM_MODULE_INVALID;
		goto cleanup;
	}
	if (!request->username)
	{
		log_error("No Username specified!");
		returnValue = RLM_MODULE_INVALID;
		goto cleanup;
	}
	if (!lotp->allowemptypassword && !request->password)
	{
		log_error("No Password specified!");
		returnValue = RLM_MODULE_INVALID;
		goto cleanup;
	}
	if (lotp->restrictusername)
	{
		if (!valid_username(request->username->vp_strvalue))
		{
			log_error("Username includes invalid characters");
			returnValue = RLM_MODULE_REJECT;
			goto cleanup;
		}
	}

	if ( lotp->realm != NULL )
	{
		if (!valid_realm(lotp->realm))
		{
			log_error("Realm includes invalid characters: %s", lotp->realm);
			returnValue = RLM_MODULE_REJECT;
			goto cleanup;
		}
	}

	if ( lotp->resConf != NULL )
	{
		if (!valid_realm(lotp->resConf))
		{
			log_error("ResConf includes invalid characters: %s", lotp->resConf);
			returnValue = RLM_MODULE_REJECT;
			goto cleanup;
		}
	}

	log_info("Doing curl_easy_init");
	curl_handle = curl_easy_init();
	if (curl_handle == NULL)
	{
		log_error("could not get curl_handle!");
		returnValue = RLM_MODULE_REJECT;
		goto cleanup;
	}
	curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, errorBuffer);

	log_info("creating the URL.");
	if (!request->password)
	{
		log_info("No password object!");
	}

	/* in case of the reply to a challenge, the client send the former state*/
	state_pair =  pairfind(request->packet->vps, PW_STATE);
	if (state_pair != NULL)
	{
		state = state_pair->vp_strvalue;
	}


	/* encode all params to one string for the post request */
	params = createUrl4Post(curl_handle, 
			lotp->realm, 
			lotp->resConf, 
			request->username->vp_strvalue, 
			request->password->vp_strvalue, 
			client_ip,
			state);

	if ( lotp->logpassword && lotp->loguser )
		log_info( "parameters created: '%s' \n", params );

	if (params == NULL)
	{
		log_error("could not allocate size for parameters!");
		returnValue = RLM_MODULE_FAIL;
		goto cleanup;
	}


	answer = sendRequest(lotp, curl_handle, params);
	if (answer == NULL) {
		if (lotp->logpassword && lotp->loguser)
			log_error("Error talking to linotpd server %s: %s.", params, errorBuffer);
		else
			log_error("Error talking to linotpd server %s: %s.", lotp->validateurl, errorBuffer);

		// Here we return a FAIL, so that the Freeradius may ask another redundant module
		returnValue = RLM_MODULE_FAIL;
		goto cleanup;
	}

	if(*answer == '\0') {
		if ( lotp->logpassword && lotp->loguser )
			log_error("No response returned for %s: %s", params, errorBuffer);
		else
			log_error("No response returned: %s", errorBuffer);
		returnValue = RLM_MODULE_FAIL;
		goto cleanup;
	}

	log_info("LinOTPd on %s returned '%s'\n", lotp->validateurl, answer);
	if (strncmp(answer, LINOTPD_REJECT, strlen(LINOTPD_REJECT)) == 0)
	{
		if (strlen(answer) > strlen(LINOTPD_REJECT)) {
			char *stat, *msg;
			if (!split_stat_and_msg(answer+strlen(LINOTPD_REJECT), &stat, &msg)) {
				log_error("Format error in reject message: %s", answer);
				returnValue = RLM_MODULE_REJECT;
				goto cleanup;
			}


			/*
			 *  Create the challenge, and add it to the reply.
			 */
			reply = pairmake("Reply-Message", msg, T_OP_EQ);
			pairadd(&request->reply->vps, reply);
			free(msg);

			state_pair = pairmake("State", stat, T_OP_EQ);
			pairadd(&request->reply->vps, state_pair);
			free(stat);

			/*
			 *  Mark the packet as an Access-Challenge packet.
			 *
			 *  The server will take care of sending it to the user.
			 */
			request->reply->code = PW_ACCESS_CHALLENGE;
			log_debug("Sending Access-Challenge.");

			returnValue = RLM_MODULE_HANDLED;

		} else {
			if ( lotp->loguser )
				log_error( "Rejecting fall-through '%s'\n", request->username->vp_strvalue);
			else
				log_error( "Rejecting fall-through\n");

			returnValue = RLM_MODULE_REJECT;
		}
		goto cleanup;
	}

	if (strcmp(answer, LINOTPD_FAIL) == 0) {
		if (lotp->loguser)
			log_error("authentication for '%s' failed", request->username->vp_strvalue);
		else
			log_error("authentication for some user failed" );

		returnValue = RLM_MODULE_INVALID;
		goto cleanup;
	}

	if (strcmp(answer, LINOTPD_OK) == 0)
	{
		if (lotp->loguser)
			log_info("user '%s' authenticated successfully", request->username->vp_strvalue);
		else
			log_info("some user authenticated successfully");

		returnValue = RLM_MODULE_OK;
		goto cleanup;
	}


 	/*
	 * default
	 */
	if (lotp->loguser)
		log_error("Rejecting fall-through '%s'\n", request->username->vp_strvalue);
	else
		log_error("Rejecting fall-through");

	returnValue	= RLM_MODULE_REJECT;

cleanup:
 	/* we're done with libcurl, so clean it up */ 
	if (curl_handle != NULL)
		curl_easy_cleanup(curl_handle);

	free(params);
	free(answer);

	return returnValue;
}

/*****************************************************************************/

module_t rlm_linotp2 = {
	RLM_MODULE_INIT,
	"LinOTP2",
	RLM_TYPE_THREAD_SAFE,	/* type: reserved */
	lotp_instantiate,	/* instantiation */
	lotp_detach,		/* detach */
	{
		lotp_auth,	/* authentication */
		NULL,		/* authorization */
		NULL,		/* preaccounting */
		lotp_acct,	/* accounting */
		NULL,		/* checksimul */
		NULL,		/* pre-proxy */
		NULL,		/* post-proxy */
		NULL		/* post-auth */
	},
};
