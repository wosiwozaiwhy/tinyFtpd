#include "common.h"
#include "sysutil.h"
#include "session.h"
#include "tunable.h"
#include "parseconf.h"
#include "ftpcodes.h"

int
main(){
	
/*
	parseconf_load_file(TINYFTPD_CONF);
	printf("pasv_enable = %d\n",tunable_pasv_enable);
	printf("port_enable = %d\n",tunable_port_enable);
	printf("listen port = %d\n",tunable_listen_port);
	printf("tunable_max_clients = %d\n",tunable_max_clients);
	printf("tunable_max_per_ip = %d\n",tunable_max_per_ip);
	printf("tunable_accept_timeout = %d\n",tunable_accept_timeout);
	printf("tunable_connect_timeout = %d\n",tunable_connect_timeout);
	printf("tunable_local_umask = %d\n",tunable_local_umask);
	printf("tunable_upload_max_rate = %d\n",tunable_upload_max_rate);
	printf("tunable_listen_address = %s\n",tunable_listen_address);

	return 0;
*/
	if( getuid()!=0 )
	{
		fprintf(stderr,"tinyFtpd : must be start as root user\n");
		exit(EXIT_FAILURE);
	}
	session_t sess = 
	{
		//control connection
		0,-1,
		"","","",
		//数据连接参数
		NULL,-1,-1,
		//process communicate
		-1,-1,
		//是否ascii模式
		0,
		//断点续传
		0,
		//重命名RNFR
		NULL
	};
	signal(SIGCHLD,SIG_IGN);
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