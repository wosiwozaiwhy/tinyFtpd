#include "ftpproto.h"
#include "sysutil.h"
void handle_child(session_t* sess)
{
	writen(sess->conn_fd,"220 (tinyFtpd)\r\n",strlen("220 (tinyFtpd)\r\n"));
	//循环读取客户端FTP请求
	while(1)
	{
		memset(sess->cmdline,0,sizeof(sess->cmdline));
		memset(sess->cmd,0,sizeof(sess->cmd));
		memset(sess->arg,0,sizeof(sess->arg));
		//读取一行数据
		readline(sess->conn_fd,sess->cmdline,MAX_COMMAND_LINE);
		//解析FTP命令与参数
		
	}
}