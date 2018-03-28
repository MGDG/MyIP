/**
  ******************************************************************************
  * @file    MyIP_DHCP.c
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   DHCP数据包打包
  ******************************************************************************
 **/
#include "MyIP_DHCP.h"
#include "MyIP_UDP.h"

#define DHCP_DEBUGOUT(...)	TCPDEBUGOUT(__VA_ARGS__)


//字段在DHCP报文中的偏移地址
#define DHCP_OP			((uint8_t)0)			//若是client送给server的封包，设为1，反向为2
#define DHCP_HTYPE		((uint8_t)1)			//硬件类别，ethernet为1
#define DHCP_HLEN		((uint8_t)2)			//硬件长度，ethernet为6
#define DHCP_HOPS		((uint8_t)3)			//若数据包需经过router传送，每站加1，若在同一网内，为0
#define DHCP_XID		((uint8_t)4)			//事务ID，是个随机数，用于客户和服务器之间匹配请求和相应消息
#define DHCP_SECS		((uint8_t)8)			//由用户指定的时间，指开始地址获取和更新进行后的时间
#define DHCP_FLAGS		((uint8_t)10)			//从0-15bits，最左一bit为1时表示server将以广播方式传送封包给 client，其余尚未使用
#define DHCP_CIADDR		((uint8_t)12)			//用户IP地址
#define DHCP_YIADDR		((uint8_t)16)			//客户IP地址(你的),分配给Client的可用IP。
#define DHCP_SIADDR		((uint8_t)20)			//用于bootstrap过程中的IP地址；
#define DHCP_GIADDR		((uint8_t)24)			//转发代理（网关）IP地址；
#define DHCP_CHADDR		((uint8_t)28)			//client的MAC地址
#define DHCP_SNAME		((uint8_t)44)			//server的名称(可选)，以0x00结尾
#define DHCP_FILE		((uint8_t)108)			//启动文件名(可选)，以0x00结尾
#define AHCP_OPTIONS	((uint8_t)236)			//可选的参数字段

/*
 Option 53 (DHCP Message Type)
 Description 
 This option is used to convey the type of the DHCP message. The code for this option is 53, and its length is 1. Legal values for this option are: 
*/
#define	DHCP_MSG_DISCOVER			((uint8_t)1)			//Client开始DHCP过程的第一个报文	[RFC2132] 
#define DHCP_MSG_OFFER				((uint8_t)2)			//Server对Discover报文的相应		[RFC2132] 
#define DHCP_MSG_REQUEST			((uint8_t)3)			//Client对Offer报文的回应，或者是Client延续IP地址租期时发出的报文 [RFC2132] 
#define DHCP_MSG_DECLINE			((uint8_t)4)			//Client发现server分配给他的ip无法使用时发出该报文通知server禁止使用该ip	[RFC2132] 
#define DHCP_MSG_ACK				((uint8_t)5)			//server对client的request报文的确认响应，client收到该报文才真正获得IP地址和相关配置信息	[RFC2132] 
#define DHCP_MSG_NAK				((uint8_t)6)			//server对client的request报文拒绝响应，client收到该报文后重新开始DHCP过程	[RFC2132] 
#define DHCP_MSG_RELEASE			((uint8_t)7)			//client主动释放server分配的IP地址，server收到该报文后回收该ip	[RFC2132] 
#define DHCP_MSG_INFORM				((uint8_t)8)			//client已经获得ip，发出此报文的目的是从DHCP Server处获得其他配置信息，如route DNS等等[RFC2132] 
#define DHCP_MSG_FORCERENEW			((uint8_t)9)			//[RFC3203]
#define DHCP_MSG_LEASEQUERY			((uint8_t)10)			//[RFC4388]
#define DHCP_MSG_LEASEUNASSIGNED	((uint8_t)11)			//[RFC4388]
#define DHCP_MSG_LEASEUNKNOWN		((uint8_t)12)			//[RFC4388]
#define DHCP_MSG_LEASEACTIVE		((uint8_t)13)			//[RFC4388]

//enum NET_STAT Pre_DHCPStat = CLOSE;
//enum NET_STAT Cur_DHCPStat = CLOSE;
bool DHCP_FinishFlg = false;
static bool ReRequestFlg = false;
static uint32_t IP_Geted_Time;											//记录获取到IP的时间，单位s
uint32_t IP_Lease_Time = 2*60*60;										//IP租约时间，单位s，默认设为2个小时
static uint8_t DHCP_Server_IP[4]={0,0,0,0};								//从DHCP服务器获取到的服务器ip
//static uint8_t DHCP_Client_IP[4]={0,0,0,0};							//从DHCP服务器获取到的客户端ip
static const uint8_t Transaction_ID[4] = {0x45,0x78,0x33,0xF5};			//随机字
static uint8_t DHCP_Option[]={0x63,0x82,0x53,0x63,						//Magic cookie: DHCP,为了与BOOTP兼容
							  0x35,0x01,0x00,							//Option: (35)DHCP Msg Type
							  0x0c,0x0d,0x4d,0x47,0x44,0x47,0x5f,0x4d,0x79,0x54,0x43,0x50,0x2F,0x49,0x50,		//Option: (12) Host Name 
							  0x32,0x04,0x00,0x00,0x00,0x00				//Option: (50) Requested IP Address
							  };

/**
  * @brief	发送DHCP Discover
  * @param	void

  * @return	void	
  * @remark
  */
void DHCP_Send_Discover(void)
{
	uint8_t data[350];

	//数组清0
	memset(data,0x00,(sizeof(data)/sizeof(data[0])) );

	//DHCP数据打包
	data[DHCP_OP] = 0x01;					//Message type: Boot Request (1)
	data[DHCP_HTYPE] = 0x01;				//Hardware type: Ethernet (0x01)
	data[DHCP_HLEN] = 0x06;					//Hardware address length: 6
	data[DHCP_HOPS] = 0x00;					//Hops: 0
	memcpy(data+DHCP_XID,Transaction_ID,4);		//Transaction ID: 0x457833f5
	data[DHCP_SECS] = 0x00;					//Seconds elapsed: 0
	data[DHCP_SECS+1] = 0x00;				//Seconds elapsed: 0
	data[DHCP_FLAGS] = 0x80;				//广播
	//DHCP_CIADDR：Client IP address: 0.0.0.0
	//DHCP_YIADDR：Your (client) IP address: 0.0.0.0
	//DHCP_SIADDR：Next server IP address: 0.0.0.0
	//DHCP_GIADDR：Relay agent IP address: 0.0.0.0
	memcpy(data+DHCP_CHADDR,My_MAC,6);		//本机MAC Client MAC address
	//DHCP_SNAME：Server host name not given
	//DHCP_FILE：Boot file name not given

	//填充Option字段
	memcpy(&data[AHCP_OPTIONS],DHCP_Option,22);
	data[AHCP_OPTIONS+6] 	= DHCP_MSG_DISCOVER;			//DHCPDISCOVER
	data[AHCP_OPTIONS+22] 	= 0xff;			//End


	//设置本地IP为0.0.0.0
	memset(MyIP_LoaclIP,0x00,sizeof(MyIP_LoaclIP)/sizeof(MyIP_LoaclIP[0]));
	
	//配置连接参数
	UDPSTRUCT tempUdp;
	memcpy(tempUdp.Re_IP,My_MACIP,4);				//远程IP为广播IP（255.255.255.255）
	memcpy(tempUdp.Re_MAC,My_MACIP,6);				//远程MAC设置为广播MAC
	tempUdp.Lc_Port = 68;							//本地客户端端口
	tempUdp.Re_Port = 67;							//远程服务器端口

	//发送UDP数据包
	Send_UDP_Bag(&MyNet[0],&tempUdp,data,259);
}

/**
  * @brief	发送DHCP Request
  * @param	void

  * @return	broadcast： 0为广播，其他为单播	
  * @remark
  */
void DHCP_Send_Request(int broadcast)
{
	uint8_t data[350];

	//数组清0
	memset(data,0x00,(sizeof(data)/sizeof(data[0])) );

	//DHCP数据打包
	data[DHCP_OP] = 0x01;						//请求
	data[DHCP_HTYPE] = 0x01;					//10M
	data[DHCP_HLEN] = 0x06;						//长度
	data[DHCP_HOPS] = 0x00;						//代理
	memcpy(data+DHCP_XID,Transaction_ID,4);		//随机数
	
	if(broadcast != 0)
	{
		data[DHCP_FLAGS] = 0x00;					//单播
		memcpy(data+DHCP_CIADDR,MyIP_LoaclIP,4);	//本机ip
	}
	else
	{
		data[DHCP_FLAGS] = 0x80;					//广播
	}
	memcpy(data+DHCP_CHADDR,My_MAC,6);			//本机MAC

	//填充Option字段
	memcpy(data+AHCP_OPTIONS,DHCP_Option,28);
	data[AHCP_OPTIONS+6] 	= DHCP_MSG_REQUEST;			//DHCP REQUEST
//	memcpy(data+AHCP_OPTIONS+24,DHCP_Client_IP,4);		//Requested IP Address
	data[AHCP_OPTIONS+28] 	= 0xff;						//End

	//配置连接参数
	UDPSTRUCT tempUdp;
	if(broadcast == 0)
		memcpy(tempUdp.Re_IP,My_MACIP,4);		//远程IP为广播IP（255.255.255.255）
	else
		memcpy(tempUdp.Re_IP,DHCP_Server_IP,4);	//远程IP为DHCP服务器IP（255.255.255.255）
	memcpy(tempUdp.Re_MAC,My_MACIP,6);			//远程MAC设置为广播MAC
	tempUdp.Lc_Port = 68;						//本地客户端端口
	tempUdp.Re_Port = 67;						//远程服务器端口

	//发送UDP数据包
	Send_UDP_Bag(&MyNet[0],&tempUdp,data,265);
}

/**
  * @brief	发送DHCP Release
  * @param	void

  * @return	void	
  * @remark
  */
void DHCP_Send_Release(void)
{
	uint8_t data[350];

	//数组清0
	memset(data,0x00,(sizeof(data)/sizeof(data[0])) );

	//DHCP数据打包
	data[DHCP_OP] = 0x01;						//请求
	data[DHCP_HTYPE] = 0x01;					//10M
	data[DHCP_HLEN] = 0x06;						//长度
	data[DHCP_HOPS] = 0x00;						//代理
	memcpy(data+DHCP_XID,Transaction_ID,4);		//随机数
	data[DHCP_FLAGS] = 0x00;					//单播
	//填充即将被释放的ip地址
	memcpy(data+DHCP_CIADDR,MyIP_LoaclIP,4);		//本机ip
	memcpy(data+DHCP_CHADDR,My_MAC,6);			//本机MAC

	//填充Option字段
	
	memcpy(data+AHCP_OPTIONS,DHCP_Option,7);
	data[AHCP_OPTIONS+6] 	= DHCP_MSG_RELEASE;			//DHCP RELEASE
	
	data[AHCP_OPTIONS+7] 	= 54;						//option 54 DHCP服务器地址
	data[AHCP_OPTIONS+8] 	= 4;						//len 4
	memcpy(data+AHCP_OPTIONS+9,DHCP_Server_IP,4);
	
	data[AHCP_OPTIONS+13] 	= 61;						//Option: (61) Client identifier
	data[AHCP_OPTIONS+14] 	= 0x07;						//Length: 7
	data[AHCP_OPTIONS+15]	= 0x01;						//Hardware type: Ethernet (0x01)
	memcpy(data+AHCP_OPTIONS+16,My_MAC,6);				//Client MAC address
	
	data[AHCP_OPTIONS+22] 	= 0xff;						//End


	//配置连接参数
	UDPSTRUCT tempUdp;
	memcpy(tempUdp.Re_IP,DHCP_Server_IP,4);
	memcpy(tempUdp.Re_MAC,My_MACIP,6);
	tempUdp.Lc_Port = 68;
	tempUdp.Re_Port = 67;
	
	//发送UDP数据包
	Send_UDP_Bag(&MyNet[0],&tempUdp,data,259);
}


/**
  * @brief	DHCP option字段处理,获取消息类型
  * @param	*data: Option的起始地址
  * @param	len:  Option的数据长度

  * @return	void	
  * @remark
  */
static uint8_t DHCP_GetMsgType(const uint8_t *data,uint16_t len)
{
	if(len < 8)
		return 0;

	for(uint16_t i=4;i<len-2;)
	{
		if(data[i]==0x35 && data[i+1]==0x01)
		{
			return data[i+2];
		}
		else
		{
			i+=data[i+1]+2;
		}
	}

	return 0;
}

/**
  * @brief	DHCP option字段处理,获取服务器地址
  * @param	*data: Option的起始地址
  * @param	len:  Option的数据长度

  * @return	void	
  * @remark Option格式 代码 长度 内容
  */
static void DHCP_GetOption(const uint8_t *data,uint16_t len)
{
	if(len < 8)
		return;
	
	for(uint16_t i=4;i<len-2;)
	{
		//查找消息类型
//		if(data[i]==0x35 && data[i+1]==0x01)
//		{
//			DHCP_DEBUGOUT("1 DHCP Msg Type: %d\r\n",data[i+2]);
//		}
//		else 
		//获取IP租约时间
		if(data[i]==0x33 && data[i+1]==0x04)
		{
			IP_Lease_Time = (((uint32_t)data[i+2])<<24) | (((uint32_t)data[i+3])<<16) | (((uint32_t)data[i+4])<<8) | (data[i+5]);
			IP_Geted_Time = MyIP_GetNowTime();			//记录获取到IP时的时间
//			DHCP_DEBUGOUT("DHCP ack IP Addr Lease Time: %u s\r\n",IP_Lease_Time);
		}
		//获取子网掩码
		else if(data[i]==0x01 && data[i+1]==0x04)
		{
			memcpy(MyIP_SubnetMask,&data[i+2],4);
//			DHCP_DEBUGOUT("DHCP ack subnet mask: %d.%d.%d.%d\r\n",MyIP_SubnetMask[0],MyIP_SubnetMask[1],MyIP_SubnetMask[2],MyIP_SubnetMask[3]);
		}
		//获取服务器地址
		else if(data[i]==0x36 && data[i+1]==0x04)
		{
			memcpy(DHCP_Server_IP,&data[i+2],4);
//			DHCP_DEBUGOUT("DHCP ack server ip: %d.%d.%d.%d\r\n",DHCP_Server_IP[0],DHCP_Server_IP[1],DHCP_Server_IP[2],DHCP_Server_IP[3]);
		}
		//获取路由器地址（网关地址）
		else if(data[i]==0x03 && data[i+1]==0x04)
		{
			memcpy(MyIP_GateWay,&data[i+2],4);
//			DHCP_DEBUGOUT("DHCP ack GateWay: %d.%d.%d.%d\r\n",MyIP_GateWay[0],MyIP_GateWay[1],MyIP_GateWay[2],MyIP_GateWay[3]);
		}

		if(data[i+1] != 0xFF)
			i+=data[i+1]+2;
		else
			break;
	}
}

/**
  * @brief	DHCP数据包处理
  * @param	*data: 接收到的所有数据
  * @param	len: 数据长度

  * @return	void	
  * @remark
  */
uint8_t DHCP_Data_Process(const uint8_t *data,uint16_t len)
{
	if(len < 286)
		return 1;			//小于最小DHCP报文长度 14EN+20IP+8UDP+236DHCP+8DHCP_Option
	
	//检查识别码，不是本机的忽略
	//识别码偏移位置 14EN + 20IP + 8UDP + XID(4)
	if(memcmp(Transaction_ID,data+46,4) != 0)
		return 2;
	
	//获取消息类型
	//偏移位置 14EN + 20IP + 8UDP + AHCP_OPTIONS = 278
	const uint16_t offset = 278;	//AHCP_OPTIONS+14+20+8;
	uint8_t DHCP_Msg_Type = DHCP_GetMsgType(data+offset,len-offset);
	
//	DHCP_DEBUGOUT("DHCP Msg Type: %d\r\n",DHCP_Msg_Type);

	switch(DHCP_Msg_Type)
	{
		case DHCP_MSG_OFFER:
		{
			//收到了DHCP服务器发来的OFFER
			if(MyNet[0].Cur_Stat == DHCP_DISCOVER)
			{
				//保存分配给本机的IP
				//暂时分配的，需客户端request并得到服务器的ACK后才能确认该IP的使用权
				//直接保存到DHCP的选项字段中，用于request的发送
				memcpy((uint8_t *)(DHCP_Option+24),data+42+DHCP_YIADDR,4);
				//进入OFFER状态，在状态机里执行，发送REQUEST
				MyNet[0].Cur_Stat = DHCP_OFFER;
			}
		}
		break;

		case DHCP_MSG_ACK:
		{
			if(ReRequestFlg)
			{
				//租约到达规定时间，重新request后返回的ACK
				ReRequestFlg = false;
				DHCP_GetOption(data+offset,len-offset);
			}
			//REQUEST状态下收到了DHCP服务器发来的ACK
			//表示IP申请成功
			else if(MyNet[0].Cur_Stat == DHCP_REQUEST)
			{
				//保存分配给本机的IP
				memcpy(MyIP_LoaclIP,data+42+DHCP_YIADDR,4);
//				DHCP_DEBUGOUT("DHCP ack client ip: %d.%d.%d.%d\r\n",MyIP_LoaclIP[0],MyIP_LoaclIP[1],MyIP_LoaclIP[2],MyIP_LoaclIP[3]);
				DHCP_GetOption(data+offset,len-offset);
				//ip获取完毕，进入ACK状态
				MyNet[0].Cur_Stat = DHCP_ACK;
			}
		}
		break;

		case DHCP_MSG_NAK:
		{
			if(!ReRequestFlg)
			{
				//IP申请失败了，需要重新申请
				//进入NACK状态重新发送Discover
				MyNet[0].Cur_Stat = DHCP_NACK;
			}
		}
		break;

#if 0
		case DHCP_MSG_REQUEST:
		break;

		case DHCP_MSG_DECLINE:
		break;
		
		case DHCP_MSG_DISCOVER:
		break;
		
		case DHCP_MSG_RELEASE:
		break;

		case DHCP_MSG_INFORM:
		break;

		case DHCP_MSG_FORCERENEW:
		break;

		case DHCP_MSG_LEASEQUERY:
		break;

		case DHCP_MSG_LEASEUNASSIGNED:
		break;

		case DHCP_MSG_LEASEUNKNOWN:
		break;

		case DHCP_MSG_LEASEACTIVE:
		break;
#endif
	}
	return 0;
}

/**
  * @brief	ip租期处理
  * @param	ElapsedTime：每次调用该函数时，已经度过的时间

  * @return	void	
  * @remark 1、在使用租期到50%后，client向server单播发送DHCPREQUEST，延续租期。
  * @remark 2、server若同意，则发送DHCPACK，client开始一个新的租用周期；若不同意，则发送DHCPNAK
  * @remark 3、client单播请求没有被同意，在租期过去87.5％时刻处，client向server广播发送
  * @remark 4、server若同意，则发送DHCPACK，client开始一个新的租用周期；若不同意，则发送DHCPNAK，租期到期后，client放弃这个IP，重新获取IP。
  */
void MyIP_IPLeaseTimeProc(void)
{
	static uint8_t flg = 0;
	uint32_t ElapsedTime;

	if(!DHCP_FinishFlg)
		return;
	
	ElapsedTime = MyIP_GetElapsedTime(IP_Geted_Time);
	
	//租约到期，重新获取IP地址
	if(ElapsedTime >= IP_Lease_Time)
	{
		if(flg != 1)
		{
			flg = 1;
			DHCP_FinishFlg = false;
			MyNet[0].Cur_Stat = DHCP_DISCOVER;
		}
	}
	//大于百分87.5
	else if(ElapsedTime > ((IP_Lease_Time>1) + (IP_Lease_Time>2)) )		
	{
		if(flg != 2)
		{
			flg = 2;
			//广播发送
			DHCP_Send_Request(0);
			ReRequestFlg = true;
		}
	}
	//大于百分50
	else if(ElapsedTime > (IP_Lease_Time>1))		
	{
		if(flg != 3)
		{
			flg = 3;
			//单播发送
			DHCP_Send_Request(1);
			ReRequestFlg = true;
		}
	}
	else
	{
		if(flg != 0)
		{
			flg = 0;
			ReRequestFlg = false;
		}
	}
}
