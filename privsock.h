#ifndef _PRIV_SOCK_H_
#define _PRIV_SOCK_H_

#include "session.h"


// 内部进程自定义协议
// 用于FTP服务进程与nobody进程进行通信

// FTP服务进程向nobody进程请求的命令
//请求PORT模式的数据连接套接字，告知nobody接收client端口号和IP地址，而后绑定套接字
#define PRIV_SOCK_GET_DATA_SOCK     1
//FTP向nobody发送2命令，请求得到是否激活的答复
#define PRIV_SOCK_PASV_ACTIVE       2
//FTP接收到PASV，则发送3命令让nobody bind个接口并listen，返回listen port
#define PRIV_SOCK_PASV_LISTEN       3
//FTP向nobody发4命令，nobody  accept请求并发回data_fd
#define PRIV_SOCK_PASV_ACCEPT       4

// nobody进程对FTP服务进程的应答
#define PRIV_SOCK_RESULT_OK         1
#define PRIV_SOCK_RESULT_BAD        2



void priv_sock_init(session_t *sess);
void priv_sock_close(session_t *sess);
void priv_sock_set_parent_context(session_t *sess);
void priv_sock_set_child_context(session_t *sess);

//发送一个char命令
void priv_sock_send_cmd(int fd, char cmd);
//取得一个char命令
char priv_sock_get_cmd(int fd);
//发送char应答
void priv_sock_send_result(int fd, char res);
//获取char应答
char priv_sock_get_result(int fd);

//发送一个整数 端口号
void priv_sock_send_int(int fd, int the_int);
//获取一个整数  端口号
int priv_sock_get_int(int fd);
//发送一个字符串(IP)
void priv_sock_send_buf(int fd, const char *buf, unsigned int len);
//接受一个字符串(IP)
void priv_sock_recv_buf(int fd, char *buf, unsigned int len);
//通过UNIX域套接字发送/接收文件描述符
void priv_sock_send_fd(int sock_fd, int fd);
int priv_sock_recv_fd(int sock_fd);


#endif /* _PRIV_SOCK_H_ */
