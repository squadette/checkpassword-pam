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

*/

#include <config.h>

#include "logging.h"

#include <errno.h>
#include <getopt.h>
#include <security/pam_appl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* command-line options processing */
static int opt_debugging = 0;

static const char* short_options = "dhs:V";

static struct option long_options[] = {
    { "debug", no_argument, NULL, 'd' },
    { "help", no_argument, NULL, 'h' },
    { "service", required_argument, NULL, 's' },
    { "version", no_argument, NULL, 'V' },
    { NULL, 0, NULL, 0 }
};

const char* usage =
"Usage: " PACKAGE " [OPTION]... -- prog...\n"
"\n"
"Authenticate using PAM and the checkpassword protocol:\n"
"\t<URL:http://cr.yp.to/checkpwd/interface.html>\n"
"and run the program specified as 'prog'\n"
"\n"
"Options are:\n"
"  -d, --debug\t\tturn on debugging output\n"
"  -h, --help\t\tdisplay this help and exit\n"
"  -s, --service=SERVICE\tspecify PAM service name to use\n"
"\t\t\t(by default use the contents of $PAM_SERVICE)\n"
"  -V, --version\t\tdisplay version information and exit\n";


/* checkpassword protocol support */
static int protocol_fd = 0;
#define PROTOCOL_LEN 512
char up[PROTOCOL_LEN];

/* pointers inside up[] */
char* username = NULL;
char* password = NULL;

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
	    response->resp = strdup(password);
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
main (int argc, char *argv[])
{
    FILE* protocol;
    int i, uplen;
    char* service_name = NULL;
    struct pam_conv pam_conversation = { conversation, NULL };
    pam_handle_t* pamh;
    int exit_status = 1;
    int retval;

    while (1) {
	int option_index = 0;
	int c = getopt_long (argc, argv, short_options, long_options, &option_index);

	if (c == -1)
	    break;

	switch (c) {
	case 'd':
	    opt_debugging = 1;
	    break;
	    
	case 'h':
	    puts(usage);
	    exit(0);

	case 's':
	    service_name = strdup(optarg);
	    if (!service_name) {
		fatal("Out of memory");
		exit(1);
	    }
	    break;	    

	case 'V':
	    puts(PACKAGE " " VERSION);
	    exit(0);
	}
    }

    if (service_name == NULL) {
	char *envval = getenv("PAM_SERVICE");
	if (!envval) {
	    fatal("PAM service name not specified");
	    exit_status = 2;
	    goto out;
	}
	service_name = strdup(envval);
	if (!service_name) {

	    fatal("Out of memory");
	    exit_status = 111;
	    goto out;
	}
    }

    /* read the username/password */
    protocol = fdopen(protocol_fd, "r");
    if (protocol == NULL) {
	fatal("Error opening fd %d: %s", protocol_fd, strerror(errno));
	exit_status = 2;
	goto out;
    }
    debugging("Reading username and password");
    uplen = fread(up, 1, PROTOCOL_LEN, protocol);
    if (uplen == 0) {
	fatal("Checkpassword protocol failure: zero bytes read");
	exit_status = 2;
	goto out;
    }
    i = 0;
    /* extract username */
    username = up + i;
    while (up[i++]) {
	if (i >= uplen) {
	    fatal("Checkpassword protocol failure: username not provided");
	    exit_status = 2;
	    goto out;
	}
    }
    debugging("Username '%s'", username);

    /* extract password */
    password = up + i;
    while (up[i++]) {
	if (i >= uplen) {
	    fatal("Checkpassword protocol failure: password not provided");
	    exit_status = 2;
	    goto out;
	}
    }
    debugging("Password '%s' read successfully", password);

    /* initialize the PAM library */
    debugging("Initializing PAM library using service name '%s'", service_name);
    retval = pam_start(service_name, username, &pam_conversation, &pamh);
    if (retval != PAM_SUCCESS) {
	fatal("Initialization failed: %s", pam_strerror(pamh, retval));
	exit_status = 111;
	goto out;
    }
    debugging("Pam library initialization succeeded");

    retval = pam_authenticate(pamh, 0);
    if (retval != PAM_SUCCESS) {
	fatal("Authentication failed: %s", pam_strerror(pamh, retval));
	exit_status = 1;
	goto out;
    }

    debugging("Authentication passed");

    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS) {
	fatal("Account management failed: %s", pam_strerror(pamh, retval));
	exit_status = 1;
	goto out;
    }
    debugging("Account management passed");

    retval = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    if (retval != PAM_SUCCESS) {
	fatal("Setting credentials failed: %s", pam_strerror(pamh, retval));
	exit_status = 1;
	goto out;
    }
    debugging("Setting PAM credentials succeeded");
    
    /* terminate the PAM library */
    debugging("Terminating PAM library");
    retval = pam_end(pamh, retval);
    if (retval != PAM_SUCCESS) {
	fatal("Terminating PAM failed: %s", pam_strerror(pamh, retval));
	exit_status = 1;
	goto out;
    }

    exit_status = 0;

 out:
    memset(up, 0x00, sizeof(up));
    debugging("Exiting with status %d", exit_status);
    exit(exit_status);
}
