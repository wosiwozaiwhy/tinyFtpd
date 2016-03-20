#include "common.h"
#include "sysutil.h"
#include "session.h"

int
main(){
	if( getuid()!=0 )
	{
		fprintf(stderr,"tinyFtpd : must be start as root user\n");
		exit(EXIT_FAILURE);
	}
	session_t sess = 
	{
		//control connection
		-1,
		"","","",
		//process communicate
		-1,-1
	}
	int listenfd = tcp_server(NULL,5188);
	//declare connect fd
	int conn;
	pid_t pid;
	while(1){
	
		conn = accept_timeout(listenfd,NULL,0);
		if(conn ==-1)
			ERR_EXIT("accept_timeout");
		pid = fork();
		if(pid == -1)
			ERR_EXIT("fork");
		if(pid ==0)
		{
			close(listenfd);
			sess.conn_fd = conn;
			start_session(&sess);
		}
		else
			close(conn);
		
	}
	return 0;
}