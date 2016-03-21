#include "str.h"
#include "common.h"

//暂时不对，没考虑周全
void str_trim_crlf(char *str)
{
	char* p = &str[strlen(str)-1];
	while(*p == '\r' || *p == '\n')
		*p-- = '\0';

}
void str_split(const char *str , char *left, char *right, char c)
{
	char* p = strchr(str,c);
	if(p == NULL)
	{
		strcpy(left,str);
	}
	else
	{
		strncpy(left,str,p-str);
		strcpy(right,p+1);
	}

}
int str_all_space(const char *str)
{
	while(*str)
	{
		if(!isspace(*str))
			return 0;
		str++;
	}
	return 1;
}
void str_upper(char *str)
{
	while(*str)
	{
		*str = toupper(*str);
		str++;
	}
}
long long str_to_longlong(const char *str)
{
	return atoll(str);
	//return 1;
}
unsigned int str_octal_to_uint(const char *str)
{
	int len = strlen(str);
	unsigned int Rst = 0,tmp =0;
	int non_zero_flag =0;
	int i =0;
	for(i =0;i!=len;i++)
	{
		tmp =str[i];
		if(!isdigit(tmp) || tmp>'7')
			return -1;
		if(tmp != '0')
			non_zero_flag =1;
		if(non_zero_flag)
			Rst = (Rst<<3) + tmp-'0';
	}
	return Rst;
}