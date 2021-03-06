#include "parseconf.h"
#include "common.h"
#include "tunable.h"
#include "str.h"

//(选项,布尔型 01)配置的数据结构和其定义的数组
static struct parseconf_bool_setting
{
  const char *p_setting_name;
  int *p_variable;
}
parseconf_bool_array[] =
{
	{ "pasv_enable", &tunable_pasv_enable },
	{ "port_enable", &tunable_port_enable },
	{ NULL, NULL }
};
//(选项，数字值)的数据结构和其定义数组
static struct parseconf_uint_setting
{
	const char *p_setting_name;
	unsigned int *p_variable;
}
parseconf_uint_array[] =
{
	{ "listen_port", &tunable_listen_port },
	{ "max_clients", &tunable_max_clients },
	{ "max_per_ip", &tunable_max_per_ip },
	{ "accept_timeout", &tunable_accept_timeout },
	{ "connect_timeout", &tunable_connect_timeout },
	{ "idle_session_timeout", &tunable_idle_session_timeout },
	{ "data_connection_timeout", &tunable_data_connection_timeout },
	{ "local_umask", &tunable_local_umask },
	{ "upload_max_rate", &tunable_upload_max_rate },
	{ "download_max_rate", &tunable_download_max_rate },
	{ NULL, NULL }
};
//(选项，字符串)的数据结构和其定义数组
static struct parseconf_str_setting
{
	const char *p_setting_name;
	const char **p_variable;
}
parseconf_str_array[] =
{
	{ "listen_address", &tunable_listen_address },
	{ NULL, NULL }
};


void parseconf_load_file(const char* path)
{
	FILE* fp = fopen(path,"r");
	if(fp==NULL)
		ERR_EXIT("fopen conf error");
	
	char setting_line[1024] = {0};
	while( fgets(setting_line,sizeof(setting_line),fp)!=NULL )
	{
		if(strlen(setting_line) == 0
			|| setting_line[0]=='#'
			||str_all_space(setting_line))
				continue;
		//去除\r\n
		str_trim_crlf(setting_line);
		parseconf_load_setting(setting_line);
		memset(setting_line,0,sizeof(setting_line));
	}
	//读取完毕，关闭文件
	fclose(fp);
}
void parseconf_load_setting(const char* setting)
{
	//去除左空格
	while(isspace(*setting))
		setting++;
	//解析存入key value
	char key[128] ={0};
	char value[128] ={0};
	str_split(setting,key,value,'=');
	if(strlen(value) == 0)
	{
		fprintf(stderr,"miss the value in config file for %s",key);
		exit(EXIT_FAILURE);
	}
	//先试着在<setting,char*>类型中找key，找到则替换原来值
	const struct parseconf_str_setting*  p_str_setting = parseconf_str_array;
	while(p_str_setting->p_setting_name!=NULL)
	{
		if( strcmp(key,p_str_setting->p_setting_name)==0 )
		{
			const char** p_cur_setting = p_str_setting->p_variable;
			//如果读取的key value与默认值冲突了，则free默认值
			if(*p_cur_setting)
				free((char*)*p_cur_setting); 
			//strdup内部分配内存，使指针可以安全指向栈上变量
			*p_cur_setting = strdup(value);
			//printf("*p_cur_setting : %d\n",**p_cur_setting);
			return;
		}
		p_str_setting++;
	}
	
	
	//试着在<setting,bool>类型中找key，找到则替换原来值
	const struct parseconf_bool_setting*  p_bool_setting = parseconf_bool_array;
	while(p_bool_setting->p_setting_name!=NULL)
	{
		if( strcmp(key,p_bool_setting->p_setting_name)==0 )
		{
			str_upper(value);
			//值为YES/NO TRUE/FALSE 1/0都行
			if(strcmp(value,"YES") == 0
				|| strcmp(value,"TRUE") == 0
				|| strcmp(value,"1") == 0)
				*(p_bool_setting->p_variable) = 1;
			else if(strcmp(value,"NO") == 0
				|| strcmp(value,"FALSE") == 0
				|| strcmp(value,"0") == 0)
				*(p_bool_setting->p_variable) = 0;
			//不合法的配置值
			else
			{
				fprintf(stderr,"miss the value in config file for %s",key);
				exit(EXIT_FAILURE);
			}
			return;
		}
		p_bool_setting++;
	}
	
	//试着在<setting,unsigned int>类型中找key，找到则替换原来值
	const struct parseconf_uint_setting*  p_uint_setting = parseconf_uint_array;
	while(p_uint_setting->p_setting_name!=NULL)
	{
		if( strcmp(key,p_uint_setting->p_setting_name)==0 )
		{
			if( strstr(key,"umask")!=NULL )
				*(p_uint_setting->p_variable) = str_octal_to_uint(value); 
			else 
				*(p_uint_setting->p_variable) = atoi(value);
			return;
		}
		p_uint_setting++;
	}
	
}