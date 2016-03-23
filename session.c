#include "session.h"
#include "privsock.h"
#include "nobody.h"
#include "ftpproto.h"

void start_session(session_t *sess){
	
	
	//if(setegid(pw->pw_gid) <0 )
		//ERR_EXIT("setegid");
	//if(seteuid(pw->pw_uid) <0)
		//ERR_EXIT("seteuid");
	/* int sockFd[2];//nobody和服务进程通信的socketPair
	if(socketpair(PF_UNIX,SOCK_STREAM,0,sockFd) < 0 )
		ERR_EXIT("socketair"); */
	 priv_sock_init(sess);
	
	pid_t pid;
	pid = fork();
	if(pid < 0)
		ERR_EXIT("son fork");
	
	if(pid ==0)
	{
		//子进程
		//服务ftp数据传输的进程
		priv_sock_set_child_context(sess);
		handle_child(sess);
	
	}
	else
	{
		
		//父进程
		//nobody进程
		priv_sock_set_parent_context(sess);
		handle_parent(sess);
		
		
		
	}
		
}