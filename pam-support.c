/* 
   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   Copyright (c) Alexey Mahotkin <alexm@hsys.msk.ru> 2002

   PAM support for checkpassword-pam

*/

#include <config.h>

#include "pam-support.h"

#include "logging.h"

#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>

static char* global_password;

static int
conversation (int num_msg, const struct pam_message **msgs,
	      struct pam_response **resp, void *appdata_ptr)
{
    int i;
    struct pam_response* responses;
    (void) appdata_ptr;

    /* safety check */
    if (num_msg <= 0) {
	fatal("Internal PAM error: num_msgs <= 0");
	return PAM_CONV_ERR;
    }

    /* allocate array of responses */
    responses = calloc(num_msg, sizeof(struct pam_response));
    if (!responses) {
	fatal("Out of memory");
	return PAM_CONV_ERR;
    }

    for (i = 0; i < num_msg; i++) {
	const struct pam_message *msg = msgs[i];
	struct pam_response* response = &(responses[i]);
	char* style = NULL;
	switch (msg->msg_style) {
	case PAM_PROMPT_ECHO_OFF: style = "PAM_PROMPT_ECHO_OFF"; break;
	case PAM_PROMPT_ECHO_ON: style = "PAM_PROMPT_ECHO_ON"; break;
	case PAM_ERROR_MSG: style = "PAM_ERROR_MSG"; break;
	case PAM_TEXT_INFO: style = "PAM_TEXT_INFO"; break;
	default: fatal("Interla error: invalid msg_style: %d", msg->msg_style); break;
	}
	debugging("conversation(): msg[%d], style %s, msg = \"%s\"", i, style, msg->msg);

	switch (msg->msg_style) {
	case PAM_PROMPT_ECHO_OFF:
	    /* reply with password */
	    response->resp = strdup(global_password);
	    if (!response->resp)
		return PAM_CONV_ERR;
	    break;

	default:
	    fatal("Internal error: unknown message style: '%s'", style);
	    return PAM_CONV_ERR;
	}
	response->resp_retcode = 0;
    }

    *resp = responses;

    return PAM_SUCCESS;
}


   
int
authenticate_using_pam (const char* service_name,
			const char* username,
			const char* password)
{
    struct pam_conv pam_conversation = { conversation, NULL };
    pam_handle_t* pamh;
    int retval;

    /* to be used later from conversation() */
    global_password = password;

    /* initialize the PAM library */
    debugging("Initializing PAM library using service name '%s'", service_name);
    retval = pam_start(service_name, username, &pam_conversation, &pamh);
    if (retval != PAM_SUCCESS) {
	fatal("Initialization failed: %s", pam_strerror(pamh, retval));
	return 111;
    }
    debugging("Pam library initialization succeeded");

    /* Authenticate the user */
    retval = pam_authenticate(pamh, 0);
    if (retval != PAM_SUCCESS) {
	/* usually PAM itself logs auth failures, but we need to see
           how it looks from our side */
	if (opt_debugging)
	    fatal("Authentication failed: %s", pam_strerror(pamh, retval));
	return 1;
    }

    debugging("Authentication passed");

    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS) {
	fatal("Account management failed: %s", pam_strerror(pamh, retval));
	return 1;
    }
    debugging("Account management succeeded");

    retval = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    if (retval != PAM_SUCCESS) {
	fatal("Setting credentials failed: %s", pam_strerror(pamh, retval));
	return 1;
    }
    debugging("Setting PAM credentials succeeded");
    
    /* terminate the PAM library */
    debugging("Terminating PAM library");
    retval = pam_end(pamh, retval);
    if (retval != PAM_SUCCESS) {
	fatal("Terminating PAM failed: %s", pam_strerror(pamh, retval));
	return 1;
    }

    return 0;
}

