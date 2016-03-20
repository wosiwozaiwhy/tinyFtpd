#ifndef _SESSION_H
#define _SESSION_H

typedef struct session
{
	//control connection
	int conn_fd,
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];
	//process communicate
	int parrent_fd;
	int child_fd;
}session_t;
void start_session(session_t *sess);


#endif //_SESSION_H_