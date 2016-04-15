#include "tunable.h"

/*默认值*/
//被动模式开关
int tunable_pasv_enable = 1;
//主动模式开关
int tunable_port_enable = 1;
//监听端口，默认21
unsigned int tunable_listen_port = 21;
//最大连接数 默认2000
unsigned int tunable_max_clients = 2000;
//默认
unsigned int tunable_max_per_ip = 50;
//接收连接超时时间，默认60s
unsigned int tunable_accept_timeout = 60;
//主动连接超时时间，默认60s
unsigned int tunable_connect_timeout = 60;
unsigned int tunable_idle_session_timeout = 300;
unsigned int tunable_data_connection_timeout = 300;
unsigned int tunable_local_umask = 077;
unsigned int tunable_upload_max_rate = 0;
unsigned int tunable_download_max_rate = 0;
const char *tunable_listen_address;
