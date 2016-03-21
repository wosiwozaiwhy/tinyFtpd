#include "session.h"

void start_session(session_t *sess){
	struct passwd* pw = getpwnam("nobody");
	if(pw == NULL)
		return;
	if(setegid(pw->pw_gid) <0 )
		ERR_EXIT("setegid");
	if(seteuid(pw->pw_uid) <0)
		ERR_EXIT("seteuid");
	int sockFd[2];//nobody和服务进程通信的socketPair
	if(socketpair(PF_UNIX,SOCK_STREAM,0,sockFd) < 0 )
		ERR_EXIT("socketair");
	
	pid_t pid;
	pid = fork();
	if(pid < 0)
		ERR_EXIT("son fork");
	
	if(pid ==0)
	{
		//子进程
		//服务ftp数据传输的进程
		close(sockFd[0]);  //子进程使用sockFd[1]与父进程通信
		sess->child_fd = sockFd[1];
		handle_child(sess);
	
	}
	else
	{
		//父进程
		//nobody进程
		close(sockFd[1]);  //父进程使用sockFd[0]与子进程通信
		sess->parent_fd = sockFd[0];
		handle_parent(sess);
		
		
		
	}
		
}