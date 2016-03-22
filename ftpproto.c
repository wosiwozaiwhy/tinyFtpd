#include "ftpproto.h"
#include "sysutil.h"
#include "str.h"
#include "ftpcodes.h"

//列出当前目录
int list_common();
//用来根据对应代码status 构造响应文本内容
void ftp_reply(session_t* sess,int status,const char* text);
//用来根据对应代码status 构造带-符号的响应文本内容
void ftp_lreply(session_t* sess,int status,const char* text);
static void do_user(session_t* sess);
static void do_pass(session_t* sess);


static void do_user(session_t *sess);
static void do_pass(session_t *sess);
static void do_cwd(session_t *sess);
static void do_cdup(session_t *sess);
static void do_quit(session_t *sess);
static void do_port(session_t *sess);
static void do_pasv(session_t *sess);
static void do_type(session_t *sess);
//static void do_stru(session_t *sess);
//static void do_mode(session_t *sess);
static void do_retr(session_t *sess);
static void do_stor(session_t *sess);
static void do_appe(session_t *sess);
static void do_list(session_t *sess);
static void do_nlst(session_t *sess);
static void do_rest(session_t *sess);
static void do_abor(session_t *sess);
static void do_pwd(session_t *sess);
static void do_mkd(session_t *sess);
static void do_rmd(session_t *sess);
static void do_dele(session_t *sess);
static void do_rnfr(session_t *sess);
static void do_rnto(session_t *sess);
static void do_site(session_t *sess);
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_size(session_t *sess);
static void do_stat(session_t *sess);
static void do_noop(session_t *sess);
static void do_help(session_t *sess);
typedef struct ftpcmd
{
	const char *cmd;
	void (*cmd_handler)(session_t *sess);
} ftpcmd_t;


static ftpcmd_t ctrl_cmds[] = {
	/* 访问控制命令 */
	{"USER",	do_user	},
	{"PASS",	do_pass	},
	{"CWD",		do_cwd	},
	{"XCWD",	do_cwd	},
	{"CDUP",	do_cdup	},
	{"XCUP",	do_cdup	},
	{"QUIT",	do_quit	},
	{"ACCT",	NULL	},
	{"SMNT",	NULL	},
	{"REIN",	NULL	},
	/* 传输参数命令 */
	{"PORT",	do_port	},
	{"PASV",	do_pasv	},
	{"TYPE",	do_type	},
	{"STRU",	/*do_stru*/NULL	},
	{"MODE",	/*do_mode*/NULL	},

	/* 服务命令 */
	{"RETR",	do_retr	},
	{"STOR",	do_stor	},
	{"APPE",	do_appe	},
	{"LIST",	do_list	},
	{"NLST",	do_nlst	},
	{"REST",	do_rest	},
	{"ABOR",	do_abor	},
	{"\377\364\377\362ABOR", do_abor},
	{"PWD",		do_pwd	},
	{"XPWD",	do_pwd	},
	{"MKD",		do_mkd	},
	{"XMKD",	do_mkd	},
	{"RMD",		do_rmd	},
	{"XRMD",	do_rmd	},
	{"DELE",	do_dele	},
	{"RNFR",	do_rnfr	},
	{"RNTO",	do_rnto	},
	{"SITE",	do_site	},
	{"SYST",	do_syst	},
	{"FEAT",	do_feat },
	{"SIZE",	do_size	},
	{"STAT",	do_stat	},
	{"NOOP",	do_noop	},
	{"HELP",	do_help	},
	{"STOU",	NULL	},
	{"ALLO",	NULL	}
};

void handle_child(session_t* sess)
{
	ftp_reply(sess,FTP_GREET,"(tinyFtpd)");
	
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
		
		/* if(strcmp("USER",sess->cmd) ==0 )
		{
			
			do_user(sess);
		}
		else if(strcmp("PASS",sess->cmd) ==0)
		{
			do_pass(sess);
		} */
		int i=0;
		int size = sizeof(ctrl_cmds)/sizeof(ctrl_cmds[0]);
		while(i<size)
		{
			if(strcmp(ctrl_cmds[i].cmd , sess->cmd) ==0)
			{
				//查找到对应cmd的命令，若handle非NULL,则说明已实现，开始处理命令
				if(ctrl_cmds[i].cmd_handler != NULL)
					ctrl_cmds[i].cmd_handler(sess);
				//未实现对应handle方法
				else
				{
					ftp_reply(sess,FTP_COMMANDNOTIMPL,"unimplement command");
				}
				break;
			}
			
			i++;
		}
		//遍历结束未找到对应命令，未识别
		if(i == size)
		{
			ftp_reply(sess,FTP_BADCMD,"unknown command");
		}
	}
}
int list_common()
{
	DIR* dir = opendir(".");
	if(dir ==NULL)
	{
		return 0;
	}
	struct dirent* dt;
	struct stat sbuf;
	while( (dt = readdir(dir))!=NULL )
	{
		if(lstat(dt->d_name,&sbuf) < 0)
		{
			continue;
		}
		char perms[] = "----------";
		perms[0] = '?';
		//获取文件类型,权限信息放入perms
		mode_t mode = sbuf.st_mode;
		switch(mode & S_IFMT)
		{
		case S_IFREG:
			perms[0] = '-';
			break;
		case S_IFLNK:
			perms[0] = 'l';
			break;
		case S_IFSOCK:
			perms[0] = 's';
			break;
		case S_IFBLK:
			perms[0] = 'b';
			break;
		case S_IFDIR:
			perms[0] = 'd';
			break;
		case S_IFCHR:
			perms[0] = 'c';
			break;
		case S_IFIFO:
			perms[0] = 'p';
			break;
		}
		//拥有者读写执行权限
		if(mode & S_IRUSR)
		{
			perms[1] = 'r';
		}
		if(mode & S_IWUSR)
		{
			perms[2] = 'w';
		}
		if(mode & S_IXUSR)
		{
			perms[3] = 'x';
		}
		//组用户读写执行权限
		if(mode & S_IRGRP)
		{
			perms[4] = 'r';
		}
		if(mode & S_IWGRP)
		{
			perms[5] = 'w';
		}
		if(mode & S_IXGRP)
		{
			perms[6] = 'x';
		}
		//其他用户读写执行权限
		if(mode & S_IROTH)
		{
			perms[7] = 'r';
		}
		if(mode & S_IROTH)
		{
			perms[8] = 'w';
		}
		if(mode & S_IROTH)
		{
			perms[9] = 'x';
		}
		//特殊权限，如uid
		if(mode & S_ISUID)
		{
			perms[3] = (perms[3]=='x')?'s','S';
		}
		if(mode & S_ISGID)
		{
			perms[6] = (perms[6]=='x')?'s','S';
		}
		if(mode & S_ISUTX)
		{
			perms[9] = (perms[9]=='x')?'s','S';
		}
		
		//打印结果到buf中
		char buf[1024] = {0};
		//@off 当前串长度
		int off =0;
		off = sprintf(buf,"%s ",perms);//文件类型和权限位
		sprintf(off + buf,"%3d %-8d %-8d",sbuf->st_nlink,st_uid,st_gid);//链接数 uid gid
	}
	
}
void ftp_reply(session_t* sess,int status,const char* text)
{
	char buf[1024] = {0};
	sprintf(buf,"%d %s\r\n",status,text);
	writen(sess->conn_fd,buf,strlen(buf));
}
void ftp_lreply(session_t* sess,int status,const char* text)
{
	char buf[1024] = {0};
	sprintf(buf,"%d-%s\r\n",status,text);
	writen(sess->conn_fd,buf,strlen(buf));
}
//处理USER
static void do_user(session_t* sess)
{   struct passwd* pw = getpwnam(sess->arg);
	if(pw == NULL)
	{	//用户不存在
		ftp_reply(sess,FTP_LOGINERR,"login incorrect");
		return;
	}
	sess->uid = pw->pw_uid;
	ftp_reply(sess,FTP_GIVEPWORD,"please specify the password");
	
}
//处理PASS
static void do_pass(session_t* sess)
{
	struct passwd* pw = getpwuid(sess->uid);
	if(pw == NULL)
	{	//用户不存在
		ftp_reply(sess,FTP_LOGINERR,"login incorrect");
		return;
	}
	struct spwd* sp = getspnam(pw->pw_name);
	if(sp == NULL)
	{	//用户对应密码不存在
		ftp_reply(sess,FTP_LOGINERR,"login incorrect");
		return;
	}
	//明文密码通过crypt函数进行加密，并与spwd中结果进行比较,用spwd->sp_pwdp做种子加密
	//使用函数char *crypt(const char *key, const char *salt); salt种子
	char* encrypted_pass = crypt(sess->arg,sp->sp_pwdp);
	//验证密码是否匹配
	if(strcmp(encrypted_pass,sp->sp_pwdp) !=0)
	{	//密码不匹配
		ftp_reply(sess,FTP_LOGINERR,"login incorrect");
		return;
	}
	//登录验证成功后当前进程改为登录用户进程
	setegid(pw->pw_gid);
	seteuid(pw->pw_uid);
	chdir(pw->pw_dir);
	ftp_reply(sess,FTP_LOGINOK,"230 login sucessful");
}

static void do_cwd(session_t *sess)
{
}
static void do_cdup(session_t *sess)
{}
static void do_quit(session_t *sess)
{}
static void do_port(session_t *sess)
{}
static void do_pasv(session_t *sess)
{}
static void do_type(session_t *sess)
{
	if(strcmp(sess->arg,"A") ==0 )
	{
		sess->is_ascii = 1;
		ftp_reply(sess,FTP_TYPEOK,"Switching to ASCII mode.");
	}
	else if(strcmp(sess->arg,"I") ==0 )
	{
		sess->is_ascii = 0;
		ftp_reply(sess,FTP_TYPEOK,"Switching to ASCII mode.");
	}
	else
	{
		ftp_reply(sess,FTP_BADCMD,"Unrecognized TYPE command.");
	}
}
//static void do_stru(session_t *sess);
//static void do_mode(session_t *sess);
static void do_retr(session_t *sess)
{}
static void do_stor(session_t *sess)
{}
static void do_appe(session_t *sess)
{}
static void do_list(session_t *sess)
{}
static void do_nlst(session_t *sess)
{}
static void do_rest(session_t *sess)
{}
static void do_abor(session_t *sess)
{}
static void do_pwd(session_t *sess)
{
	char text[1024] = {0};
	char dir[1024+1] = {0};
	getcwd(dir,1024);
	sprintf(text,"\"%s\"",dir);
	ftp_reply(sess,FTP_PWDOK,text);
	
}
static void do_mkd(session_t *sess)
{}
static void do_rmd(session_t *sess)
{}
static void do_dele(session_t *sess)
{}
static void do_rnfr(session_t *sess)
{}
static void do_rnto(session_t *sess)
{}
static void do_site(session_t *sess)
{}
static void do_syst(session_t *sess)
{
	ftp_reply(sess,FTP_SYSTOK,"UNIX Type: L8");
}
static void do_feat(session_t *sess)
{
	
	ftp_lreply(sess,FTP_FEAT,"Features:");
	writen(sess->conn_fd," EPRT\r\n",sizeof(" EPRT\r\n"));
	writen(sess->conn_fd," EPSV\r\n",sizeof(" EPSV\r\n"));
	writen(sess->conn_fd," MDTW\r\n",sizeof(" MDTW\r\n"));
	writen(sess->conn_fd," PASV\r\n",sizeof( " PASV\r\n"));
	writen(sess->conn_fd," REST_STREAM\r\n",sizeof(" REST_STREAM\r\n"));
	writen(sess->conn_fd," SIZE\r\n",sizeof(" SIZE\r\n"));
	writen(sess->conn_fd," TVFS\r\n",sizeof(" TVFS\r\n"));
	writen(sess->conn_fd," UTF8\r\n",sizeof(" UTF8\r\n"));
	writen(sess->conn_fd," EPRT\r\n",sizeof(" EPRT\r\n"));
	writen(sess->conn_fd," EPRT\r\n",sizeof(" EPRT\r\n"));
	ftp_reply(sess,FTP_FEAT,"End\r\n"); 
}
static void do_size(session_t *sess)
{}
static void do_stat(session_t *sess)
{}
static void do_noop(session_t *sess)
{}
static void do_help(session_t *sess)
{}