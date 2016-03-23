#include "nobody.h"
#include "sysutil.h"
#include "privsock.h"
#include "tunable.h"

static void privop_pasv_get_data_sock(session_t *sess);
static void privop_pasv_active(session_t *sess);
static void privop_pasv_listen(session_t *sess);
static void privop_pasv_accept(session_t *sess);

void handle_parent(session_t* sess)
{
	//修改父进程为nobody进程
	struct passwd* pw = getpwnam("nobody");
	if(pw == NULL)
		return;
	if(setegid(pw->pw_gid) < 0)
		ERR_EXIT("sete    gid");
	if(seteuid(pw->pw_gid) < 0)
		ERR_EXIT("seteuid");
	 
	char cmd;
	while(1)
	{
		//从子进程接收命令
		cmd = priv_sock_get_cmd(sess->parent_fd);
		//解析内部命令，处理
		switch(cmd)
		{
		//ftp进程发出PORT模式的指令
		case PRIV_SOCK_GET_DATA_SOCK :
			privop_pasv_get_data_sock(sess);
			break;
		case PRIV_SOCK_PASV_ACTIVE :
			privop_pasv_active(sess);
			break;
		case PRIV_SOCK_PASV_LISTEN :
			privop_pasv_listen(sess);
			break;
		case PRIV_SOCK_PASV_ACCEPT :
			privop_pasv_accept(sess);
			break;
		
		}
	
	}
}

static void privop_pasv_get_data_sock(session_t *sess)
{
	unsigned short port = (unsigned short)priv_sock_get_int(sess->parent_fd);
	char ip[16] = {0};
	priv_sock_recv_buf(sess->parent_fd, ip, sizeof(ip));
	
	struct sockaddr_in addr;
	memset(&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);
	//建立连接
	int fd = tcp_client(20);
	if(fd == -1)
	{
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}
	if(connect_timeout(fd,&addr,tunable_connect_timeout)<0)
	{
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		close(fd);
		return ;
	}
	
	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	priv_sock_send_fd(sess->parent_fd,fd);
	close(fd);
	
}
static void privop_pasv_active(session_t *sess)
{
}
static void privop_pasv_listen(session_t *sess)
{
}
static void privop_pasv_accept(session_t *sess)
{
}
