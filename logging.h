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

   Provide logging facilities

*/

#ifndef LOGGING_H_
#define LOGGING_H_ 1

#include <stdio.h>
#include <syslog.h>

extern int opt_use_stdout;
extern int opt_debugging;

#define init_logging(id) \
  do { \
    openlog(id, LOG_PID, LOG_AUTH); \
  } while (0)


#define terminate_logging() \
  do { \
    closelog(); \
  } while (0)


#define fatal(msg, args...) \
  do { \
    if (opt_use_stdout) { \
      fprintf(stderr, msg , ##args); \
      fputc('\n', stderr); \
    } else { \
      syslog(LOG_ERR, msg , ##args); \
    } \
  } while (0)


#define debugging(msg, args...) \
  do { \
    if (opt_debugging) { \
      if (opt_use_stdout) { \
        fprintf(stderr, msg , ##args); \
        fputc('\n', stderr); \
      } else { \
        syslog(LOG_DEBUG, msg , ##args); \
      } \
    } \
  } while (0)


#endif /* LOGGING_H_ */
