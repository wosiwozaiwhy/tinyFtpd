#ifndef _STR_H_
#define _STR_H_

//去除字符串结尾的\r\n
void str_trim_crlf(char *str);
//根据第一个c把str分成left和right 两部分
void str_split(const char *str , char *left, char *right, char c);
//判断str是否全为space
int str_all_space(const char *str);
//str全部转为大写
void str_upper(char *str);
//类似atoi 把str转换成long long 类型返回
long long str_to_longlong(const char *str);
//str转成unsigned int 返回
unsigned int str_octal_to_uint(const char *str);

  

#endif //_STR_H_