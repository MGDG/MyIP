/**
  ******************************************************************************
  * @file    MyIP_TCPIP.h
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   
  ******************************************************************************
 **/
#ifndef _MYIP_TCPIP_H
#define _MYIP_TCPIP_H

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "stm32f4xx_hal.h"
#include "MyIP_Transfer.h"

#define TCPDEBUGOUT(...)  printf(__VA_ARGS__)

//typedef unsigned          char uint8_t;
//typedef unsigned short     int uint16_t;
//typedef unsigned           int uint32_t;

extern uint8_t My_MACIP[6];//广播地址
extern uint8_t My_MAC[6];//MAC
extern uint8_t MyIP_LoaclIP[4];//本地IP地址
extern uint8_t MyIP_SubnetMask[4];//子网掩码
extern uint8_t MyIP_GateWay[4]; //默认网关


#define MYTCPMSS				((uint16_t)0x0400U)					//(1024)最大报文长度,最大可接收的数据长度，不包含EN_Head,IP_Head.TCP_Head;
#define TCP_KEEPALIVE_TIME		((uint16_t)20)						//tcp_keepalive_time（开启keepalive的闲置时长，单位S）
#define TCP_KEEPALIVE_INTVL		((uint16_t)5)						//tcp_keepalive_intvl（keepalive探测包的发送间隔，单位S）
#define TCP_KEEPALIVE_PROBES	((uint16_t)9)						//tcp_keepalive_probes（如果对方不予应答，探测包的发送次数）

//定义网络类型
enum NET_TYPE
{
	UDP_CLIENT=1,
	UDP_SERVER=2,
	TCP_CLIENT=4,
	TCP_SERVER=8,
};

//定义连接状态
enum NET_STAT
{
	CLOSE,					//关闭
	
  	DHCP_DISCOVER,
	DHCP_OFFER,
	DHCP_REQUEST,
	DHCP_ACK,				//收到服务器的ACK后状态转入CLOSE
	DHCP_NACK,
	DHCP_RENEW,
	
	ARP_REQUEST,
	ARP_ANSWER,
	RARP_REQUEST,
	RARP_ANSWER,
	
	UDP_CONNECT,			//建立连接
	UDP_TRANSFER,			//UDP数据传输状态
	
	TCP_LISTEN,				//TCP监听，服务器状态
	TCP_SYNRECEIVED,		//TCP 收到对方的SYN，但还没收到自己发过去的SYN的ACK
	TCP_SYNSENT,			//TCP 正在试图主动建立连接[发送SYN后还没有收到ACK]
	TCP_ESTABLISHED,		//TCP 已连接，数据传送状态
	TCP_FINWAIT1,
	TCP_FINWAIT2,
	TCP_CLOSING,
	TCP_TIMEWAIT,
	TCP_CLOSEWAIT,
	TCP_LASTASK,
};

//连接的各个状态
union NET_FLG
{
	struct 
	{
		uint8_t Used		:1;			//该连接是否已经被使用
		uint8_t ARPOK		:1;			//arp获取MAC地址完成
		uint8_t KeepAlive	:1;			//keep_alive使能标志位
		uint8_t Data_Sent	:1; 		//收到数据
		uint8_t Data_Recv	:1; 		//发送数据
		uint8_t Wait_Ack	:1;			//等待对方应答
	}reg;
	uint8_t flg;
};

//定义一个连接的结构
typedef struct
{
	uint8_t  Re_IP[4];				//远程IP
	uint8_t  Re_MAC[6];				//远程MAC
	uint8_t  IP_TTL;				//生存周期
	uint16_t IP_Mark;				//标示字段
	uint16_t Lc_Port;				//本地端口
	uint16_t Re_Port;				//远程端口
	uint32_t TCP_Mark;				//序号
	uint32_t TCP_CMark;				//确认序号
	uint32_t Time_Count;			//计时时间
	uint32_t TCP_WaitTime;			//keepalive等待时间
	uint8_t Re_Sent;				//重发次数
	union NET_FLG Net_Flg;			//各个标志位
	enum NET_STAT Pre_Stat;			//连接状态
	enum NET_STAT Cur_Stat;			//连接状态
	enum NET_TYPE Net_Type;			//使用协议，是TCP还是UDP


	uint8_t EN_Head[14];			//以太网协议以太网首部 [14]
	uint8_t IP_Head[20];			//IP协议首部 [20]
	uint8_t UDP_Head[8];			//UDP协议首部 [8]
	uint8_t TCP_Head[60];			//TCP协议首部 [60]
	uint8_t ARP_Head[28];			//ARP数据 [28]
	uint8_t ICMP_Data[40];			//ICMP数据 [40]
}LINKSTRUCT;

struct SocketAddr
{
	const char *IP;
	uint16_t Port;
};

extern LINKSTRUCT MyNet[3];

void MyIP_Init(void);
uint16_t MyIP_GetLocalPort(void);

uint32_t MyIP_CheckSum(const uint16_t *p,uint16_t len);
uint16_t MyIP_CheckCode(uint32_t sum);
bool MyIP_CheckSocket(uint8_t Protocol,uint16_t Lport,uint16_t *NetIndex);

void MyIP_Run(void);
void MyIP_TimeRefresh(void);
uint32_t MyIP_GetNowTime(void);
uint32_t MyIP_GetElapsedTime(uint32_t PreTime);

uint16_t MyIP_Socket(uint8_t Protocol);
int MyIP_Bind(uint16_t sockfd,uint16_t LcPort);
int MyIP_Connect(uint16_t sockfd,const struct SocketAddr *dest_addr);
int MyIP_Listen(uint16_t sockfd,int ListenNum);
int MyIP_Close(uint16_t sockfd);
int MyIP_Sendto(uint16_t sockfd,const uint8_t *data,uint16_t len);
uint16_t MyIP_revcfrom(uint16_t sockfd,const uint8_t *data,uint16_t MaxLen);

#endif
