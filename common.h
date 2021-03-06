#ifndef _COMMON_H_
#define _COMMON_H_

#include<unistd.h>
#include<errno.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<sys/types.h>
#include<netdb.h>
#include<fcntl.h>
#include<arpa/inet.h>
#include "pwd.h"
#include "shadow.h"
#include "crypt.h"
#include "signal.h"
#include<linux/capability.h>
#include<sys/syscall.h>
#include <sys/sendfile.h>


#include <time.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/stat.h>

#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<ctype.h>

#define ERR_EXIT(m) \
  do \
  { \
    perror(m); \
	exit(EXIT_FAILURE); \
  } \
  while (0)

#define MAX_COMMAND_LINE 1024
#define MAX_COMMAND 32
#define MAX_ARG 1024
#define TINYFTPD_CONF  "config"
#endif //_COMMON_H_
