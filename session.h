#ifndef _SESSION_H
#define _SESSION_H
#include "common.h"
typedef struct session
{
	//control connection
	uid_t uid;
	int conn_fd;
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];
	//process communicate
	//父子进程通信的sockfd
	int parent_fd;
	int child_fd;
	
	//协议状态
	//是否ascii模式
	int is_ascii;
} session_t;
void start_session(session_t *sess);


#endif //_SESSION_H_