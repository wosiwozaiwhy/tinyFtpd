#include "ftpproto.h"
#include "sysutil.h"
#include "str.h"

//用来根据对应代码status 构造响应文本内容
void ftp_reply(session_t* sess,int status,const char* text);
static void do_user(session_t* sess);
static void do_pass(session_t* sess);


void handle_child(session_t* sess)
{
	ftp_reply(sess->conn_fd,FTP_GREET,"(tinyFtpd)");
	
	//循环读取客户端FTP请求
	int ret;
	while(1)
	{
		memset(sess->cmdline,0,sizeof(sess->cmdline));
		memset(sess->cmd,0,sizeof(sess->cmd));
		memset(sess->arg,0,sizeof(sess->arg));
		//读取一行数据
		ret = readline(sess->conn_fd,sess->cmdline,MAX_COMMAND_LINE);
		//读取一行失败，结束当前进程
		if(ret <0 )
			ERR_EXIT("readline");
		//ret==0 : 客户端断开了连接，结束当前进程
		else if(ret ==0)
			exit(EXIT_SUCCESS);
		//去除\r\n
		str_trim_crlf(sess->cmdline);
		printf("cmdline = [%s]\n",sess->cmdline);
		//解析出cmd  arg
		str_split(sess->cmdline, sess->cmd, sess->arg,' ');
		printf("cmd = [%s]  arg = [%s]\n",sess->cmd,sess->arg);
		//解析处理FTP命令与参数
		//命令转化为大写
		str_upper(sess->cmd);
		
		if(strcmp("USER",sess->cmd) ==0 )
		{
			
			do_user(sess);
		}
		else if(strcmp("PASS",sess->cmd) ==0)
		{
			do_pass(sess);
		}
	}
}

void ftp_reply(session_t* sess,int status,const char* text)
{
	char buf[1024] = {0};
	sprintf(buf,"%d %s\r\n",status,text);
	writen(sess->conn_fd,buf,strlen(buf);
}

//处理USER
static void do_user(session_t* sess)
{   struct passwd* pw = getpwnam(sess->arg);
	if(pw == NULL)
	{
		ftp_reply(sess->conn_fd,FTP_LOGINERR,"login incorrect");
	}
	ftp_reply(sess->conn_fd,FTP_GIVEPWORD,"please specify the password");
	
}
//处理PASS
static void do_pass(session_t* sess)
{
	ftp_reply(sess->conn_fd,FTP_LOGINOK,"230 login sucessful");
}