#include "ftpproto.h"
#include "sysutil.h"
#include "str.h"

void handle_child(session_t* sess)
{
	writen(sess->conn_fd,"220 (tinyFtpd)\r\n",strlen("220 (tinyFtpd)\r\n"));
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
		printf("cmdline = [%s]\n",sess->cmdline);
		str_trim_crlf(sess->cmdline);
		printf("cmdline = [%s]\n",sess->cmdline);
		str_split(sess->cmdline, sess->cmd, sess->arg,' ');
		printf("cmd = [%s]  arg = [%s]\n",sess->cmd,sess->arg);
		//解析FTP命令与参数
		
	}
}