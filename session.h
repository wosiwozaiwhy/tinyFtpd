#ifndef _SESSION_H
#define _SESSION_H
#include "common.h"
typedef struct session
{
	//被动模式下本机监听的ip值
	char localip[20];
	//control connection
	uid_t uid;
	int conn_fd;
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];
	
	//数据连接参数
	struct sockaddr_in* port_addr;
	//数据传输套接字 用来连接client成功后/监听client主动连接后传输数据
	int data_fd;
	//监听套接字 用来接收client连接 被动
	int listen_fd;
	//process communicate 
	//父子进程通信的sockfd
	int parent_fd;
	int child_fd;
	
	/*协议状态*/
	//是否ascii模式 
	int is_ascii;
	//断点续传
	long long restart_pos;
	//重命名RNFR
	char* rnfr_name;
	//限速用变量
	unsigned int uplaod_rate_max;
	unsigned int download_rate_max;
	long start_sec;//开始传输时间
	long start_usec;
	
	
} session_t;
void start_session(session_t *sess);


#endif //_SESSION_H_