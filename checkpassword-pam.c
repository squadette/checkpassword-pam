/* 
   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   Copyright (c) Alexey Mahotkin <alexm@hsys.msk.ru> 2002-2004

*/

#include <config.h>

#include "logging.h"
#include "pam-support.h"

#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* command line options processing */
int opt_debugging = 0;
static int opt_dont_set_env = 0;
static int opt_dont_chdir_home = 0;
int opt_use_stdout = 0;

static const char* short_options = "dehs:V";

enum { OPT_STDOUT = 1 };
static struct option long_options[] = {
    { "debug", no_argument, NULL, 'd' },
    { "help", no_argument, NULL, 'h' },
    { "noenv", no_argument, NULL, 'e' },
    { "no-chdir-home", no_argument, NULL, 'H' },
    { "service", required_argument, NULL, 's' },
    { "stdout", no_argument, NULL, OPT_STDOUT },
    { "version", no_argument, NULL, 'V' },
    { NULL, 0, NULL, 0 }
};

static const char* usage =
"Usage: " PACKAGE " [OPTION]... -- prog...\n"
"\n"
"Authenticate using PAM and the checkpassword protocol:\n"
"\t<URL:http://cr.yp.to/checkpwd/interface.html>\n"
"and run the program specified as 'prog'\n"
"\n"
"Options are:\n"
"  -d, --debug\t\tturn on debugging output\n"
"  -e, --noenv\t\tdo not set uid, gid, environment variables, \n\t\t\tand home directory\n"
"  -H, --no-chdir-home\tdo not change to home directory\n"
"  -h, --help\t\tdisplay this help and exit\n"
"  -s, --service=SERVICE\tspecify PAM service name to use\n"
"\t\t\t(by default use the contents of $PAM_SERVICE)\n"
"  -V, --version\t\tdisplay version information and exit\n";


/* checkpassword protocol support */
#define PROTOCOL_FD 3
#define PROTOCOL_LEN 512
static char up[PROTOCOL_LEN];

/* pointers into up[] */
static char* username = NULL;
static char* password = NULL;

int
main (int argc, char *argv[])
{
    FILE* protocol;
    int i, uplen;
    struct passwd* pw;
    char* service_name = NULL;
    int exit_status = 1;

    init_logging(argv[0]);

    /* process command line options */
    opterr = 0;
    while (1) {
	int option_index = 0;
	int c = getopt_long (argc, argv, short_options, long_options, &option_index);

	if (c == -1)
	    break;

	switch (c) {
	case OPT_STDOUT:
	    opt_use_stdout = 1;
	    break;

	case 'd':
	    opt_debugging = 1;
	    break;

	case 'e':
	    opt_dont_set_env = 1;
	    break;

	case 'H':
	    opt_dont_chdir_home = 1;
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
	    fatal("Invalid command line, see --help");
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

    terminate_logging();
    init_logging(service_name);

    /* read the username/password */
    protocol = fdopen(PROTOCOL_FD, "r");
    if (protocol == NULL) {
	fatal("Error opening fd %d: %s", PROTOCOL_FD, strerror(errno));
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

    if (opt_dont_set_env)
      goto execute_program; /* skip setting up process environment */

    /* switch to proper uid/gid/groups */
    pw = getpwnam(username);
    if (!pw) {
	if (opt_debugging)
	    fatal("Error getting information about %s from /etc/passwd: %s", username, strerror(errno));
	exit_status = 2;
	goto out;
    }

    /* set supplementary groups */
    if (initgroups(username, pw->pw_gid) == -1) {
	fatal("Error setting supplementary groups for user %s: %s", username, strerror(errno));
	exit_status = 111;
	goto out;
    }

    /* set gid */
    if (setgid(pw->pw_gid) == -1) {
	fatal("setgid(%d) error: %s", pw->pw_gid, strerror(errno));
	exit_status = 111;
	goto out;
    }

    /* set uid */
    if (setuid(pw->pw_uid) == -1) {
	fatal("setuid(%d) error: %s", pw->pw_uid, strerror(errno));
	exit_status = 111;
	goto out;
    }

    if (!opt_dont_chdir_home) {
	/* switch to user home directory */
	if (chdir(pw->pw_dir) == -1) {
	    fatal("Error changing directory %s: %s", pw->pw_dir, strerror(errno));
	    exit_status = 1;
	    goto out;
	}
    }

    /* set $USER */
    if (setenv("USER", username, 1) == -1) {
	fatal("Error setting $USER to %s: %s", username, strerror(errno));
	exit_status = 111;
	goto out;
    }

    /* set $HOME */
    if (setenv("HOME", pw->pw_dir, 1) == -1) {
	fatal("Error setting $HOME to %s: %s", pw->pw_dir, strerror(errno));
	exit_status = 111;
	goto out;
    }

    /* set $SHELL */
    if (setenv("SHELL", pw->pw_shell, 1) == -1) {
	fatal("Error setting $SHELL to %s: %s", pw->pw_shell, strerror(errno));
	exit_status = 111;
	goto out;
    }

 execute_program:

    /* execute the program, if any */
    if (optind < argc) {
	debugging("Executing %s", argv[optind]);

	execvp(argv[optind], argv + optind);
	fatal("Cannot exec(%s): %s\n", argv[optind], strerror(errno));
	exit_status = 2;
	goto out;
    }
    /* if no program was provided in command line, simply exit */

 out:
    memset(up, 0x00, sizeof(up));

    debugging("Exiting with status %d", exit_status);

    terminate_logging();

    exit(exit_status);
}
