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
// not needed with curl 7.1 anymore
//#include	<curl/types.h>
//#include 	<curl/easy.h>

#define log(level, format, ...) \
	radlog(level, "rlm_linotp: " format, ## __VA_ARGS__)
#define error(format, ...) \
	log(L_ERR, format, ## __VA_ARGS__)

#define log_info(format, ...) \
	log(L_INFO, format, ## __VA_ARGS__)
	
#define log_error(format, ...) \
	log(L_ERR, format, ## __VA_ARGS__)	

#define debug(format, ...) \
	log(L_ERR, "(%s) " format, __FUNCTION__, ## __VA_ARGS__)

// libltdl is so buggy...add this in radius.h

#define lt__PROGRAM__LTX_preloaded_symbols lt_libltdl_LTX_preloaded_symbols

// username and password was correct
#define LINOTPD_OK			":-)"
#define LINOTPD_REJECT		":-("
#define LINOTPD_FAIL		":-/"

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
} lotp_inst_t;

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
	if (!lotp->validateurl )
	{
		log_error("options are incomplete");
		free(lotp);
		return -1;
	}

	*instancep = lotp;
	return 0;
}

static int lotp_detach(void *instance)
{
	lotp_inst_t *lotp = instance;
	if (lotp)
	{
		memset(lotp, 0, sizeof(*lotp));
		free(lotp);
	}
	return 0;
}

/*****************************************************************************/

static int lotp_acct(void *instance, REQUEST *request)
{
	return RLM_MODULE_NOOP;
}

/*****************************************************************************/

static int inline valid_char(unsigned char c)
{
	int i;

	/* We disallow anything except known good */
	const char allowed_nonalpha[] = "-_+.@";
	
	/* a-z A-Z 0-9*/
	if (isalnum(c))
		return 1;

	/* Non-alphanumeric */
	for (i=0; i < sizeof(allowed_nonalpha)-1; i++)
		if (c == allowed_nonalpha[i])
			return 1;
			
	/* Invalid */
	return 0;
}

static int inline valid_realm_char(unsigned char c)
{
	int i;

	/* We disallow anything except known good */
	const char allowed_nonalpha[] = "-_";

	/* a-z A-Z 0-9*/
	if (isalnum(c))
		return 1;

	/* Non-alphanumeric */
	for (i=0; i < sizeof(allowed_nonalpha)-1; i++)
			if (c == allowed_nonalpha[i])
					return 1;

	/* Invalid */
	return 0;
}


#ifndef LINOTP_MAX_USERNAME_LEN
#define LINOTP_MAX_USERNAME_LEN 256
#endif

#ifndef LINOTP_MAX_REALMNAME_LEN
#define LINOTP_MAX_REALMNAME_LEN 256
#endif


static int inline valid_username(char *s)
{
	size_t len = 0;

	while (*s)
	{
		if (!valid_char(*s))
			return 0;

		if (++len >= LINOTP_MAX_USERNAME_LEN)
			return 0;

		++s;
	}

	return 1;
}

static int inline valid_realm(char *s )
{
	size_t len = 0;
	if (*s == NULL)
	{
		return 1;
	}
	while (*s)
	{
		if (!valid_realm_char(*s))
			return 0;
		if (++len >= LINOTP_MAX_REALMNAME_LEN)
			return 0;
		++s;
	}
	return 1;
}

/***********************************************
   Curl stuff
***********************************************/
struct MemoryStruct {
  char *memory;
  size_t size;
};

static void *myrealloc(void *ptr, size_t size)
{
	void * ret = NULL;

	if (size > 1024 * 1024)
	{
		ret = NULL;
	}

	/* There might be a realloc() out there that doesn't like reallocing
	NULL pointers, so we take care of it here */
	if(ptr)
		ret = realloc(ptr, size);
	else
		ret = malloc(size);

	return ret;
}
 
static size_t WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *data)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)data;

	/* failsafe */
	if (realsize > 1024*1024)
	{
		error("The linotpd responded to our authentication request with more than 1MB of data! Something is really wrong here!");
		return mem->size;
	}

	mem->memory = myrealloc(mem->memory, mem->size + realsize + 1);
	if (mem->memory)
	{
		memcpy(&(mem->memory[mem->size]), ptr, realsize);
		mem->size += realsize;
		mem->memory[mem->size] = 0;
	}
	return realsize;
}


char * createUrl4Post(CURL *curl_handle,
		char * realm,
		char * resConf,
		char * user,
		char * password,
		char * client,
		char * state)
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
	char * arry[argc][2];

	/* the return value */
	char *param = NULL;


	log_debug("entering createUrl4Post.");
	/*** initialize array****/
	for (i= 0; i< argc; i++)
	{
		arry[i][0] = NULL; arry[i][1] = NULL;
	}
	i = 0;
	if ( realm != NULL )
	{
		arry[i][0] = "realm";
		arry[i][1] = curl_easy_escape(curl_handle, realm, 0);
		i++;
	}
	if ( resConf != NULL )
	{
		arry[i][0] = "resConf";
		arry[i][1] = curl_easy_escape(curl_handle, resConf, 0);
		i++;
	}
	if ( user != NULL )
	{
		arry[i][0] = "user";
		arry[i][1] = curl_easy_escape(curl_handle, user, 0);
		i++;
	}
	if ( password != NULL )
	{
		arry[i][0] = "pass";
		arry[i][1] = curl_easy_escape(curl_handle, password, 0);
		i++;
	}
	if ( client != NULL )
	{
		arry[i][0] = "client";
		arry[i][1] = curl_easy_escape(curl_handle, client, 0);
		i++;
	}
	if ( state != NULL )
	{
		arry[i][0] = "state";
		arry[i][1] = curl_easy_escape(curl_handle,state, 0);
		i++;
	}

	/* now we calculate the required size of the param str*/
	int length= 0;
	for (i= 0; i< argc; i++)
	{
		if (arry[i][0] != NULL) 
		{
			log_debug("[%d] %s=%s\n", i, arry[i][0], arry[i][1]);
			length = length + strlen(arry[i][0]) + 1; /* add 1 for '&'*/
			length = length + strlen(arry[i][1]) + 1; /* add 1 for '='*/
		}
	}

	size = (length +1) *sizeof(char);
	log_debug("allocating %d chars", size);
	param = (char*) calloc(size, sizeof(char));

	/* concat the values in the param string*/
	memset(param,'\0',size);
	for (i= 0; i< argc; i++){
		if (arry[i][0] != NULL && arry[i][1] != NULL) {
			if (i>0) strcat(param,"&");
			strcat(param, arry[i][0]);
			strcat(param, "=");
			strcat(param, arry[i][1]);

			/* finally clean up the escaped data*/
			log_debug("freeing escaped value for %s", arry[i][0]);
			curl_free(arry[i][1]);
		}
	}


	return param;

}

int sendRequest(CURL *curl_handle, char * url, char * params,
		struct MemoryStruct * chunk,
		int nosslhostnameverify, int nosslcertverify, lotp_inst_t *lotp)
{
	int all_status	= 0;
	int status	= 0;

	/* Setup the base url */
 	status 	    = curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	all_status += status;

	/* Now specify the POST data */ 
	status 	    = curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, params);
 	all_status += status;

 	if (status)
 	{
		if ( lotp->logpassword && lotp->loguser )
		{
			log_error("Error setting option CURLOPT_URL %s: %i", params, status);
		}
		else
		{
			log_error("Error setting option CURLOPT_URL %s: %i", lotp->validateurl, status);
		}
 	}
 	status 		= curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
 	all_status += status;

 	if (status)
 	{
		log_error("Error setting option CURLOPT_WRITEFUNCTION: %i", status);
 	}

 	status 		= curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, chunk);
	all_status += status;

 	if (status)
 	{
		log_error("Error setting option CURLOPT_WRITEDATA: %i", status);
 	}

	status 		= curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
	all_status += status;
	if (status)
	{
		log_error("Error setting option CURLOPT_USERAGENT: %i", status);
	}
 	if ( nosslhostnameverify )
 	{
		status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
 	}
	else
	{
		status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 2L);
	}
	all_status += status;
	if (status)
	{
		log_error("Error setting option CURLOPT_SSL_VERIFYHOST: %i", status);
	}

 	if ( nosslcertverify )
 	{
 		status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
 	}
	else
	{
 		status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);
	}
 	all_status += status;

 	if (status)
 	{
		log_error("Error setting option CURLOPT_SSL_VERIFYPEER: %i", status);
 	}

 	status 		= curl_easy_perform(curl_handle);
 	all_status += status;
 	if (status)
 	{
		if ( lotp->logpassword && lotp->loguser )
		{
			log_error("Error in curl_easy_perform: %i, url: %s", status, url);
		}
		else
		{
			log_error("Error in curl_easy_perform: %i, url: %s", status, lotp->validateurl);
		}
	}
	curl_easy_cleanup(curl_handle);

	return all_status;

}


void split_stat_and_message(char * s, char ** stat, char ** msg)
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

/********** LinOTP stuff ***************************/

static int lotp_auth(void *instance, REQUEST *request)
{
	/* quiet the compiler */
	instance = instance;
	request = request;

	VALUE_PAIR *state_pair;
	char * state = NULL;
	VALUE_PAIR *reply;

	char errorBuffer[CURL_ERROR_SIZE];
	CURL *	curl_handle		= NULL;
	CURLcode all_status		= 0;

	lotp_inst_t *lotp 		= instance;
	int nosslhostnameverify = ( !lotp->sslhostnameverify );
 	int nosslcertverify		= ( !lotp->sslcertverify );

	int returnValue		    	= RLM_MODULE_REJECT;
	char *params 			= NULL;
	
	char * shortname	= request->client->shortname;  // maybe we can use this (the definition from clients.conf) one day
	char * client_ip    = NULL;
	int size = 100;
	int nchars = 0;
	
	// allocate the memory for client_ip string
	log_info("getting client ip now.");
	client_ip = (char*) malloc (size);
	if (client_ip == NULL)
	{
		log_error("could not allocate size for client_ip");
		goto cleanup;
	}
	memset(client_ip,'\0',size);
	VALUE_PAIR *vp;
	switch (request->packet->src_ipaddr.af) {
	case AF_INET:
		log_debug("got a IPv4 client address");
		/* check for the nas ip or as fallback the request client ip*/
		vp = pairfind(request->packet->vps, PW_NAS_IP_ADDRESS);
		if (!vp) {
			log_debug("found PW_NAS_IP_ADDRESS");
			vp = radius_paircreate(request, &request->packet->vps,
			                       PW_NAS_IP_ADDRESS,
			                       PW_TYPE_IPADDR);
			vp->vp_ipaddr = request->packet->src_ipaddr.ipaddr.ip4addr.s_addr;
		} else {
			vp = pairfind(request->packet->vps, PW_PACKET_SRC_IP_ADDRESS);
			if (!vp) {
				log_debug("found PW_PACKET_SRC_IP_ADDRESS");
				vp = radius_paircreate(request, &request->packet->vps,
									   PW_PACKET_SRC_IP_ADDRESS,
									   PW_TYPE_IPADDR);
				vp->vp_ipaddr = request->packet->src_ipaddr.ipaddr.ip4addr.s_addr;
			}
		}
		if (!vp) {
			log_error("Found no IPv4 address");
		} else {
			snprintf(client_ip, size-1, "%s", inet_ntoa(request->packet->src_ipaddr.ipaddr.ip4addr));
		}
		break;
	case AF_INET6:
		log_debug("got a IPv6 client address");
		/* check for the nas ip or as fallback the request client ip*/
		vp = pairfind(request->packet->vps, PW_NAS_IPV6_ADDRESS);
		if (!vp) {
			log_debug("found PW_NAS_IPV6_ADDRESS");
			vp = radius_paircreate(request, &request->packet->vps,
						PW_NAS_IPV6_ADDRESS,
						PW_TYPE_IPV6ADDR);
			memcpy(vp->vp_strvalue,
						&request->packet->src_ipaddr.ipaddr,
						sizeof(request->packet->src_ipaddr.ipaddr));
		} else {
			vp = pairfind(request->packet->vps, PW_PACKET_SRC_IPV6_ADDRESS);
			if (!vp) {
				log_debug("found PW_PACKET_SRC_IPV6_ADDRESS");
				vp = radius_paircreate(request, &request->packet->vps,
							PW_PACKET_SRC_IPV6_ADDRESS,
							PW_TYPE_IPV6ADDR);
				memcpy(vp->vp_strvalue,
							&request->packet->src_ipaddr.ipaddr,
							sizeof(request->packet->src_ipaddr.ipaddr));
			}
 		}
		if (!vp) {
			log_error("Found no IPv6 address");
		} else {
			snprintf(client_ip, size-1, "%s", vp->vp_strvalue);
		}
		break;
	default:
		log_error("Unknown address family for packet source.");
		break;
	}
	log_info("something");
	log_info("got client ip: %s.", client_ip);


	struct MemoryStruct chunk;
		chunk.memory		= NULL; /* we expect realloc(NULL, size) to work */
		chunk.size 		= 0;    /* no data at this point */

	curl_global_init(CURL_GLOBAL_ALL);

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
		goto cleanup;
	}


	all_status = sendRequest(curl_handle, lotp->validateurl, params,
			(void *)&chunk, nosslhostnameverify, nosslcertverify, lotp);

	if (all_status != 0)
	{
		if ( lotp->logpassword && lotp->loguser )
		{
			log_error("Error talking to linotpd server %s: %s. See CURLcode in curl.h for detailes (%i)",
					params, errorBuffer, all_status);
		}
		else
		{
			log_error("Error talking to linotpd server %s: %s. See CURLcode in curl.h for detailes (%i)",
					lotp->validateurl, errorBuffer, all_status);
		}
		// Here we return a FAIL, so that the Freeradius may ask another redundant module
		returnValue = RLM_MODULE_FAIL;
		goto cleanup;
	}

	/*
	* Now, our chunk.memory points to a memory block that is chunk.size
	* bytes big and contains the remote file.
	* You should be aware of the fact that at this point we might have an
	* allocated data block, and nothing has yet deallocated that data. So when
	* you're done with it, you should free() it as a nice application.
	*/
	if(chunk.memory == NULL)
	{
		if ( lotp->logpassword && lotp->loguser )
			log_error("No response returned for %s: %s", params, errorBuffer);
		else
			log_error("No response returned: %s", errorBuffer);
		goto cleanup;
	}

	log_info("LinOTPd on %s returned '%s'\n", lotp->validateurl, chunk.memory);
	if (strncmp(chunk.memory, LINOTPD_REJECT, strlen(LINOTPD_REJECT)) == 0)
	{
		if (strlen(chunk.memory) > strlen(LINOTPD_REJECT)) 
		{
			char * stat = "";
			char * msg  = "";
			split_stat_and_message(chunk.memory,&stat,&msg);

			/*
			 *  Create the challenge, and add it to the reply.
			 */
			reply = pairmake("Reply-Message", msg, T_OP_EQ);
			pairadd(&request->reply->vps, reply);
			state_pair = pairmake("State", stat, T_OP_EQ);
			pairadd(&request->reply->vps, state_pair);

			/*
			 *  Mark the packet as an Access-Challenge packet.
			 *
			 *  The server will take care of sending it to the user.
			 */
			request->reply->code = PW_ACCESS_CHALLENGE;
			log_debug("Sending Access-Challenge.");

			returnValue = RLM_MODULE_HANDLED;

		}
		else
		{
			if ( lotp->loguser )
				log_error( "Rejecting fall-through '%s'\n", request->username->vp_strvalue);
			else
				log_error( "Rejecting fall-through\n");
			returnValue	= RLM_MODULE_REJECT;
		}
		goto cleanup;
	}

	if (strcmp(chunk.memory, LINOTPD_FAIL) == 0)
	{
		if ( lotp->loguser )
			log_error( "authentication for '%s' failed", request->username->vp_strvalue);
		else
			log_error( "authentication for some user failed" );
		returnValue = RLM_MODULE_INVALID;
		goto cleanup;
	}
	if (strcmp(chunk.memory, LINOTPD_OK) == 0)
	{
		if ( lotp->loguser )
			log_info( "user '%s' authenticated successfully", request->username->vp_strvalue);
		else
			log_info( "some user authenticated successfully");
		returnValue = RLM_MODULE_OK;
		goto cleanup;
	}
 	{//default
		if ( lotp->loguser )
			log_error( "Rejecting fall-through '%s'\n", request->username->vp_strvalue);
		else
			log_error( "Rejecting fall-through" );
 		returnValue	= RLM_MODULE_REJECT;
 		goto cleanup;
 	}

 cleanup:

 	/* we're done with libcurl, so clean it up */ 
	curl_global_cleanup();

	free(params);

	if (chunk.memory != NULL)
	{
		free(chunk.memory);
	}
	if (client_ip != NULL)
	{
		free(client_ip);
	}
	return returnValue;
}

/*****************************************************************************/

module_t rlm_linotp2 = {
	RLM_MODULE_INIT,
	"LinOTP2",
	RLM_TYPE_THREAD_UNSAFE,  /* type: reserved */
	lotp_instantiate,      /* instantiation */
	lotp_detach,           /* detach */
	{
		lotp_auth,         /* authentication */
		NULL,              /* authorization */
		NULL,              /* preaccounting */
		lotp_acct,         /* accounting */
		NULL,              /* checksimul */
		NULL,			   /* pre-proxy */
		NULL,			   /* post-proxy */
		NULL			   /* post-auth */
	},
};

