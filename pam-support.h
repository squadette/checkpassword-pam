/* 
   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   Copyright (c) Alexey Mahotkin <squadette@gmail.com> 2002-2005

   PAM support for checkpassword-pam

*/

#ifndef PAM_SUPPORT_H_
#define PAM_SUPPORT_H_ 1

int authenticate_using_pam (const char* service_name,
			    const char* username,
			    char* password);

#endif /* PAM_SUPPORT_H_ */

