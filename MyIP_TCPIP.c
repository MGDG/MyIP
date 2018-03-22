/**
  ******************************************************************************
  * @file    MyIP_TCPIP.c
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   
  ******************************************************************************
 **/
#include "MyIP_TCPIP.h"
#include "MyIP_ARP.h"
#include "MyIP_TCP.h"
#include "MyIP_UDP.h"
#include "MyIP_ICMP.h"
#include "MyIP_IP.h"
#include "MyIP_NetState.h"

//时间
static volatile uint32_t MyTCPIPTime_Sec = 0;			//时间，每格一秒需要加1
//相关参数设置,指定IP
uint8_t My_MACIP[6]={255,255,255,255,255,255};//广播地址
uint8_t My_MAC[6]={0xAB,0xCD,0X34,0X56,0XAB,0XCD};//MAC
#if 1
uint8_t MyIP_LoaclIP[4]={0,0,0,0};//本地IP地址
uint8_t MyIP_SubnetMask[4]={0,0,0,0};//子网掩码
uint8_t MyIP_GateWay[4]={0,0,0,0}; //默认网关
#else
uint8_t MyIP_LoaclIP[4]={192,168,1,231};//本地IP地址
uint8_t MyIP_SubnetMask[4]={255,255,255,0};//子网掩码
uint8_t MyIP_GateWay[4]={192,168,1,1}; //默认网关
#endif


LINKSTRUCT MyNet[3];
uint16_t sockfd,sockfd2;
	
void MyIP_Init(void)
{
	MyNet[0].Net_Type = TCP_SERVER;
	MyNet[0].Cur_Stat = TCP_LISTEN;
	MyNet[0].Lc_Port = 1233;
	MyNet[0].Pre_Stat = CLOSE;
	MyNet[0].Cur_Stat = DHCP_DISCOVER;
		
	
	struct SocketAddr socketaddr;
	uint8_t tempip[4] = {14,215,177,38};
	memcpy(socketaddr.ReIP,tempip,4);
	socketaddr.RePort = 80;
//	uint8_t tempip[4] = {192,168,1,80};
//	memcpy(socketaddr.ReIP,tempip,4);
//	socketaddr.RePort = 8235;
	sockfd = MyIP_Socket(TCP_CLIENT);
	if(sockfd != 0)
	{
		MyIP_Bind(sockfd,1234);
		MyIP_Connect(sockfd,&socketaddr);
		TCPDEBUGOUT("socket success (%d)\r\n",sockfd);
	}
	
	struct SocketAddr addr2;
	uint8_t tempip2[4] = {192,168,1,80};
	memcpy(addr2.ReIP,tempip2,4);
	addr2.RePort = 8235;
	sockfd = MyIP_Socket(TCP_SERVER);
	if(sockfd != 0)
	{
		MyIP_Bind(sockfd,1235);
		MyIP_Connect(sockfd,&addr2);
		TCPDEBUGOUT("socket success (%d)\r\n",sockfd);
	}
	

//	struct SocketAddr socketaddr2;
//	uint8_t tempip2[4] = {192,168,1,219};
//	memcpy(socketaddr2.ReIP,tempip2,4);
//	socketaddr2.RePort = 8234;
//	socket2 = MyIP_Socket(TCP_CLIENT,&socketaddr2);
//	if(socket2 != -1)
//	{
//		TCPDEBUGOUT("socket success (%d)\r\n",socket2);
//		MyIP_Bind(socket2,1234);
//	}
}

/**
  * @brief	获取一个本地端口，不能重复
  * @param	void

  * @return	本地端口号	
  * @remark	所指的端口是相对与本地连接来说的
  */
uint16_t GetLocalPort(void)
{
	static uint16_t tPort=0;
	uint16_t i;
	if(++tPort>20000)						//0~19999之间变化
	{
		tPort=0;							//如果第一轮端口端口号已经分配完成
		uint16_t NetNum = sizeof(MyNet)/sizeof(MyNet[0]);
		while(1)
		{
			for(i=0;i<NetNum;i++)
			{
				if(MyNet[i].Lc_Port==tPort+10000)
					break;					//已存在
			}
			if(i>=NetNum)break;				//不存在，则直接退出
			else tPort++;					//存在，则加1，再退出
		}
	}
	return 10000+tPort;
}

/**
  * @brief	刷新连接的远程IP
  * @param	node： 连接指针
  * @param	ipbuf: IP数组

  * @return	bool	
  * @remark		
  */
bool MyNetConfig_ReIP(LINKSTRUCT *node,const uint8_t *ipbuf)
{
	if(node == NULL || ipbuf == NULL)
		return false;
	
	memcpy(node->Re_IP,ipbuf,4);
	
	return true;
}

/**
  * @brief	刷新连接的远程MAC
  * @param	node： 连接指针
  * @param	macbuf: MAC数组

  * @return	bool	
  * @remark		
  */
bool MyNetConfig_ReMAC(LINKSTRUCT *node,const uint8_t *macbuf)
{
	if(node == NULL || macbuf == NULL)
		return false;
	
	memcpy(node->Re_MAC,macbuf,6);
	
	return true;
}


/**
  * @brief	检验和累加函数
  * @param	*p：字符数组
  * @param	len：长度

  * @return	32位累加和	
  * @remark		
  */
uint32_t TCPIP_Check_Sum(const uint16_t *p,uint16_t len)
{
	uint16_t tem;
	uint32_t checkcode=0;			//检验和

	if(len==0)
		return 0;				//长度为0直接返回0

	if(p==NULL)
		return 0;

	for(uint16_t i=0;i<len/2;i++)			//循环总长度除以2次,如果为寄数,则少循环一次
	{
		checkcode += *p++;
	}

	if((len&0x01)==0x01)			//如果为奇数,则还需要加1个
	{
		//不能直接左移，要考虑大小端点
//		tem = *(uint8_t *)p;
//		tem <<= 8;
//		checkcode += tem;
		
		//这样子可能会造成指针越界
//		tem = *p;
//		tem &= 0x00FF;
//		checkcode += tem;
		
		tem = *(uint8_t *)p;
		tem &= 0x00FF;
		checkcode += tem;
	}

	return checkcode;
}


/**
  * @brief	处理累加和的溢出位函数
  * @param	sum：32位累加和

  * @return	16位和校验值	
  * @remark		
  */
uint16_t TCPIP_Check_Code(uint32_t sum)
{
//	uint16_t tem;
//	//如果进位就需要加到尾部 
//	while(sum>0xFFFF)
//	{
//		tem = sum>>16;				//得到高位
//		sum &= 0xFFFF;				//去掉高位
//	    sum += tem;					//加到低位
//	}
//	tem=sum;
//	return ~tem;
	
	sum = (sum>>16) + (sum & 0xffff);   //将高16bit与低16bit相加
	sum += (sum>>16);              //将进位到高位的16bit与低16bit 再相加
	return (uint16_t)(~sum);
}

/**
  * @brief	在本地连接中查找端口一致的连接
  * @param	Protocol: 协议类型
  * @param	Lport: 本地端口
  * @param	*NetIndex: 本地连接序号

  * @return	bool	
  * @remark	所指的端口是相对与本地连接来说的
  */
bool TCPIP_Check_Socket(uint8_t Protocol,uint16_t Lport,uint16_t *NetIndex)
{
	uint16_t NetNum = sizeof(MyNet)/sizeof(MyNet[0]);

	for(uint16_t i=1;i<NetNum;i++)
	{
		if( (MyNet[i].Lc_Port==Lport) && ((MyNet[i].Net_Type & Protocol) != 0) )
		{
			*NetIndex = i;
			return true;
		}
	}
	
	return false;
}

/**
  * @brief	从网卡中读出数据并进行处理
  * @param	void

  * @return	uint8_t	
  * @remark	
  */
static uint8_t Data_Receive(void)
{
	uint8_t data[2048];
	uint16_t len=MyIP_PacketReceive(data,sizeof(data)/sizeof(data[0]));	 //接收数据
	
	if(len>sizeof(data)/sizeof(data[0]) || len<14)							//14为最小数据包,以太网首部
		return 1;

	if(data[13]==0x06)
	{
		return ARP_Data_Process(data,len);
	}
	else if(data[13]==0x00)
	{
		return IP_Data_Process(data,len);
	}
	else
	{
//		TCPDEBUGOUT("unknow bag: %02X\r\n",data[13]);
		return 3;
	}
}


void MyIP_Run(void)
{
	Data_Receive();
	My_NetState();
}

/**
  * @brief	时间刷新
  * @param	void

  * @return	void
  * @remark	不考虑溢出，必须每隔一秒钟调用一次
  */
void MyTCPIPTime_Refresh(void)
{
	MyTCPIPTime_Sec++;
}

uint32_t MyTCPIPTime_GetNowTime(void)
{
	return MyTCPIPTime_Sec;
}

/**
  * @brief	获取已经流逝的时间
  * @param	PreTime: 之前的时间

  * @return	uint32_t
  * @remark
  */
uint32_t MyTCPIPTime_GetElapsedTime(uint32_t PreTime)
{
	if(MyTCPIPTime_Sec >= PreTime)
		return (MyTCPIPTime_Sec-PreTime);
	else
		return (0xFFFFFFFF-PreTime+MyTCPIPTime_Sec);
}

/**
  * @brief	申请一个socket
  * @param	Protocol： 连接类型 UDP_CLIENT、UDP_SERVER、TCP_CLIENT、TCP_SERVER
  * @param	*dest_addr： 远程IP和端口

  * @return	sockfd
  * @remark
  */
uint16_t MyIP_Socket(uint8_t Protocol)
{
	uint16_t NetNum = sizeof(MyNet)/sizeof(MyNet[0]);

	if((Protocol!=UDP_CLIENT) && (Protocol!=UDP_SERVER) && (Protocol!=TCP_CLIENT) && (Protocol!=TCP_SERVER))
		return 0;
	
	for(uint16_t i=1;i<NetNum;i++)
	{
		//该连接未被使用
		if(0 == MyNet[i].Net_Flg.reg.Used)
		{
			//全部清0
			memset(&MyNet[i],0x00,sizeof(MyNet[i]));
			//初始化该连接的各个参数
			MyNet[i].Net_Type = (enum NET_TYPE)Protocol;
			
			MyNet[i].Pre_Stat = CLOSE;
			MyNet[i].Cur_Stat = CLOSE;
		
			//该连接标记为已使用
			MyNet[i].Net_Flg.reg.Used = 1;
			
			//返回当前连接序号
			return i;
		}
	}
	
	//没找到可用的连接
	return 0;
}

/**
  * @brief	申请一个socket
  * @param	sockfd:  连接
  * @param	LcPort： 本地端口

  * @return	int
  * @remark
  */
int MyIP_Bind(uint16_t sockfd,uint16_t LcPort)
{
	uint16_t NetNum = sizeof(MyNet)/sizeof(MyNet[0]);
	if( (sockfd>=NetNum) || (sockfd<1) )
		return 1;
	
	//要查重，防止跟其他连接使用同一个端口
	for(uint16_t i=0;i<NetNum;i++)
	{
		if( (MyNet[i].Lc_Port==LcPort)  &&  (i != sockfd) )
		{
			return 2;
		}
	}
	
	MyNet[sockfd].Lc_Port = LcPort;
	
	return 0;
}

/**
  * @brief	申请一个socket
  * @param	sockfd:  连接
  * @param	*dest_addr： 远程IP和端口

  * @return	int
  * @remark
  */
int MyIP_Connect(uint16_t sockfd,const struct SocketAddr *dest_addr)
{
	uint16_t NetNum = sizeof(MyNet)/sizeof(MyNet[0]);
	if( (sockfd>=NetNum) || (sockfd<1) )
		return 1;
	
	//连接未初始化
	if(0 == MyNet[sockfd].Net_Flg.reg.Used)
		return 2;
	
	//连接不处于关闭状态
	if(MyNet[sockfd].Cur_Stat != CLOSE)
		return 3;
	
	//初始化该连接的各个参数
	memcpy(MyNet[sockfd].Re_IP,dest_addr->ReIP,4);		//初始化远程IP
	MyNet[sockfd].Re_Port = dest_addr->RePort;			//初始化远程端口
	
	//如果是TCP客户端或者UDP的话
	if(MyNet[sockfd].Net_Type != TCP_SERVER)
	{
		if(MyNet[sockfd].Net_Type == TCP_CLIENT)
		{
			MyNet[sockfd].IP_TTL = 128;
			MyNet[sockfd].TCP_Mark = 0x1200;					//序号
			MyNet[sockfd].TCP_CMark = 0;
			MyNet[sockfd].Cur_Stat = TCP_SYNSENT;
		}
		//如果是UDP
		else
		{
			MyNet[sockfd].Cur_Stat = UDP_CONNECT;
		}
		return 0;
	}
	//为TCP服务器的话,调用listen等待对方连接即可
	else
	{
		return 4;
	}
}

/**
  * @brief	开始监听客户端连接
  * @param	sockfd: 连接
  * @param	ListenNum： 支持的连接数量（该功能暂未实现）

  * @return	int
  * @remark
  */
int MyIP_Listen(uint16_t sockfd,int ListenNum)
{
	uint16_t NetNum = sizeof(MyNet)/sizeof(MyNet[0]);
	if( (sockfd>=NetNum) || (sockfd<1) )
		return 1;
	
	//连接未初始化
	if(0 == MyNet[sockfd].Net_Flg.reg.Used)
		return 2;
	
	//判断协议类型
	if(MyNet[sockfd].Net_Type != TCP_SERVER)
		return 3;
	
	//连接不处于关闭状态
	if(MyNet[sockfd].Cur_Stat != CLOSE)
		return 4;
	
	MyNet[sockfd].IP_TTL = 128;
	MyNet[sockfd].TCP_Mark = 0x1200;					//序号
	MyNet[sockfd].TCP_CMark = 0;
	MyNet[sockfd].Cur_Stat = TCP_LISTEN;
	
	return 0;
}

/**
  * @brief	关闭一个连接（只支持客户端断开连接）
  * @param	sockfd: 连接

  * @return	int
  * @remark
  */
int MyIP_Close(uint16_t sockfd)
{
	uint16_t NetNum = sizeof(MyNet)/sizeof(MyNet[0]);
	if( (sockfd>=NetNum) || (sockfd<1) )
		return 1;
	
	//连接未初始化
	if(0 == MyNet[sockfd].Net_Flg.reg.Used)
		return 2;
	
	//判断连接协议类型
	if(MyNet[sockfd].Net_Type == TCP_SERVER)
	{
		if( (MyNet[sockfd].Cur_Stat != TCP_ESTABLISHED) && (MyNet[sockfd].Cur_Stat!=TCP_LISTEN) )
		{
			return 3;
		}
		else
		{
			if(0 == Send_TCP_Bag(&MyNet[sockfd],(TCPFLG_FIN|TCPFLG_ACK),NULL,0))
			{
				//向客户端发送完断开连接信号后，服务器状态转入CLOSEWAIT
				MyNet[sockfd].Cur_Stat = TCP_CLOSEWAIT;
				return 0;
			}
			else
			{
				return 4;
			}
		}
	}
	else if(MyNet[sockfd].Net_Type == TCP_CLIENT)
	{
		if(MyNet[sockfd].Cur_Stat != TCP_ESTABLISHED)
		{
			return 5;
		}
		else
		{
			if(Send_TCP_Bag(&MyNet[sockfd],(TCPFLG_FIN|TCPFLG_ACK),NULL,0) == 0)
			{
				MyNet[sockfd].Cur_Stat = TCP_FINWAIT1;
				return 0;
			}
			else
			{
				return 6;
			}
		}
	}
	else
	{
		//是UDP的话，直接进入关闭状态
		MyNet[sockfd].Cur_Stat = CLOSE;
		return 0;
	}
}

/**
  * @brief	发送数据
  * @param	sockfd: 连接
  * @param	*data: 数据
  * @param	len: 数据长度

  * @return	int
  * @remark 返回0表示发送成功
  */
int MyIP_Sendto(uint16_t sockfd,const uint8_t *data,uint16_t len)
{
	uint16_t NetNum = sizeof(MyNet)/sizeof(MyNet[0]);
	if( (sockfd>=NetNum) || (sockfd<1) )
		return 1;
	
	//连接未初始化
	if(0 == MyNet[sockfd].Net_Flg.reg.Used)
		return 2;
	
	//判断连接协议类型
	if( (MyNet[sockfd].Net_Type==TCP_SERVER) || (MyNet[sockfd].Net_Type==TCP_CLIENT) )
	{
		if(MyNet[sockfd].Cur_Stat != TCP_ESTABLISHED)
			return 3;
		
		return Send_TCP_Bag(&MyNet[sockfd],(TCPFLG_ACK|TCPFLG_PSH),data,len);
	}
	else
	{
		if(MyNet[sockfd].Cur_Stat != UDP_TRANSFER)
			return 4;
		
		UDPSTRUCT tempUdp;
		memcpy(tempUdp.Re_IP,MyNet[sockfd].Re_IP,4);
		memcpy(tempUdp.Re_MAC,MyNet[sockfd].Re_MAC,6);
		tempUdp.Lc_Port = MyNet[sockfd].Lc_Port;
		tempUdp.Re_Port = MyNet[sockfd].Re_Port;
		
		//发送UDP数据包
		Send_UDP_Bag(&MyNet[sockfd],&tempUdp,data,len);
		
		return 0;
	}
}

/**
  * @brief	接收数据
  * @param	sockfd: 连接
  * @param	*data: 数据
  * @param	MaxLen: 允许接收的最大长度

  * @return	uint16_t 实际接收的长度
  * @remark
  */
uint16_t MyIP_revcfrom(uint16_t sockfd,const uint8_t *data,uint16_t MaxLen)
{
	uint16_t NetNum = sizeof(MyNet)/sizeof(MyNet[0]);
	if( (sockfd>=NetNum) || (sockfd<1) )
		return 1;
	
	//连接未初始化
	if(0 == MyNet[sockfd].Net_Flg.reg.Used)
		return 2;
	
	//从对应的socket队列中读取数据
	
	//返回实际读取到的数据大小
	return MaxLen;
}
