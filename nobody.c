#include "nobody.h"
#include "sysutil.h"
void handle_parent(session_t* sess)
{
	char cmd;
	//接收服务子进程的socket信息，处理
	while(1)
	{
		read(sess->parent_fd,&cmd,1);
		//解析处理命令
	}
}