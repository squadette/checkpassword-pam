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
#include "pam-support.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* command-line options processing */
int opt_debugging = 0;
int opt_use_stdout = 0;

static const char* short_options = "dhs:V";

enum { OPT_STDIN = 1, OPT_STDOUT = 2 };
static struct option long_options[] = {
    { "debug", no_argument, NULL, 'd' },
    { "help", no_argument, NULL, 'h' },
    { "service", required_argument, NULL, 's' },
    { "stdin", no_argument, NULL, OPT_STDIN },
    { "stdout", no_argument, NULL, OPT_STDOUT },
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
static int protocol_fd = 3;
#define PROTOCOL_LEN 512
char up[PROTOCOL_LEN];

/* pointers inside up[] */
char* username = NULL;
char* password = NULL;

int
main (int argc, char *argv[])
{
    FILE* protocol;
    int i, uplen;
    char* service_name = NULL;
    int exit_status = 1;

    init_logging();

    /* process command-line options */
    opterr = 0;
    while (1) {
	int option_index = 0;
	int c = getopt_long (argc, argv, short_options, long_options, &option_index);

	if (c == -1)
	    break;

	switch (c) {
	case OPT_STDIN:
	    protocol_fd = 0;
	    break;

	case OPT_STDOUT:
	    opt_use_stdout = 1;
	    break;

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

	case '?':
	    fatal("Invalid command-line, see --help");
	    exit(2);
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
    debugging("Password read successfully");

    /* authenticate using PAM */
    exit_status = authenticate_using_pam(service_name, username, password);
    if (exit_status != 0)
	goto out;

 out:
    memset(up, 0x00, sizeof(up));

    terminate_logging();

    debugging("Exiting with status %d", exit_status);
    exit(exit_status);
}
