#include "nobody.h"
#include "sysutil.h"
#include "privsock.h"
#include "tunable.h"
#include "common.h"

//消除capset的警告,因头文件未暴露这个接口，而capset又是系统调用。
int capset(cap_user_header_t hdrp, const cap_user_data_t datap)
{
	return syscall(__NR_capset,hdrp,datap);
}
//收取FTP发过来的端口 IP 主动模式进行，bind21端口，连接client IP
static void privop_pasv_get_data_sock(session_t *sess);
//响应ftp 被动模式是否激活的请求
static void privop_pasv_active(session_t *sess);
//响应ftp 被动模式监听是否开启的请求
static void privop_pasv_listen(session_t *sess);
static void privop_pasv_accept(session_t *sess);
//设置此进程pid和特权
void set_privilege(void);


void handle_parent(session_t* sess)
{
	
	
	set_privilege();

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

//设置此进程pid和特权
void set_privilege()
{
//修改父进程为nobody进程
	struct passwd* pw = getpwnam("nobody");
	if(pw == NULL)
		return;
	if(setegid(pw->pw_gid) < 0)
		ERR_EXIT("sete    gid");
	if(seteuid(pw->pw_gid) < 0)
		ERR_EXIT("seteuid");
	
	/*给当前进程增加bind 系统端口(<1024)的权限
	使用CAPABILITY机制
	 int capset(cap_user_header_t hdrp, const cap_user_data_t datap);
	typedef struct __user_cap_header_struct {
              __u32 version;
              int pid;
           } *cap_user_header_t;

    typedef struct __user_cap_data_struct {
              __u32 effective;
              __u32 permitted;
              __u32 inheritable;
           } *cap_user_data_t;
	*/
	struct __user_cap_header_struct  cap_header;
	struct __user_cap_data_struct    cap_data;
	memset(&cap_header,0,sizeof(cap_header));
	memset(&cap_data,0,sizeof(cap_data));
	cap_header.version =  _LINUX_CAPABILITY_VERSION_1;
	cap_header.pid = 0;//cap_get才写入pid，cap_set不需要写入
	//cap_mask 放入 bind_service
	__u32 cap_mask = 0;
	cap_mask |= (1<< CAP_NET_BIND_SERVICE);
	cap_data.effective = cap_data.permitted =cap_mask;
	//exec替换时是否继承
	cap_data.inheritable = 0;
	
	capset(&cap_header,&cap_data);
}

static void privop_pasv_get_data_sock(session_t *sess) 
{
	unsigned short port = (unsigned short)priv_sock_get_int(sess->parent_fd);
	char ip[16] = {0};
	priv_sock_recv_buf(sess->parent_fd, ip, sizeof(ip));
	//client 地址addr
	struct sockaddr_in addr;
	memset(&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);
	//绑定20端口号，建立连接，返回socket fd
	int fd = tcp_client(sess->localip,20);
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
	int active = 0;
	if(sess->listen_fd != -1)
	{
		active = 1;
	}
	priv_sock_send_int(sess->parent_fd,active);	
}
static void privop_pasv_listen(session_t *sess)
{
	//char ip[16] = {0};
	//getlocalip(ip);
	sess->listen_fd= tcp_server(sess->localip,0);
	
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	//获取本地sockfd信息
	if(getsockname(sess->listen_fd,(struct sockaddr*)&addr,&addrlen) < 0)
	{
		ERR_EXIT("getsockname");
	}
	//响应PASV发送的port和ip均为主机字节序
	unsigned short port = ntohs(addr.sin_port);
	
	//port发送给ftp进程
	priv_sock_send_int(sess->parent_fd,port);
	
}
static void privop_pasv_accept(session_t *sess)
{
	
	int fd = accept_timeout(sess->listen_fd,NULL,tunable_accept_timeout);
	close(sess->listen_fd);
	//接收失败
	if( fd == -1)
	{	
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}
	else 
	{
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
		priv_sock_send_fd(sess->parent_fd,fd);
		close(fd);
	}
	
}
