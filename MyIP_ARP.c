/**
  ******************************************************************************
  * @file    MyIP_ARP.c
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   
  ******************************************************************************
 **/
#include "MyIP_ARP.h"
#include "MyIP_Enthernet.h"
  
#define ARP_DEBUGOUT(...)	TCPDEBUGOUT(__VA_ARGS__)

union ARP_FLG
{
	struct 
	{
		uint8_t ActivFlg		:1;			//该连接是否已经被使用
	}reg;
	uint8_t flg;
};

struct
{
	uint8_t IP[4];				//记录IP地址
	uint8_t MAC[6];				//记录对应的MAC地址
	union ARP_FLG Flg;			//各个状态标记
	uint32_t LiveTime;			//该记录存活时间,单位S
}ARP_Cache[10];					//可存放的缓存数量


/**
  * @brief	判断远程ip是否为局域网
  * @param	*node： 连接

  * @return	bool	
  * @remark	true 内网， false 外网
  */
static bool Is_LAN(const uint8_t *Re_IP)
{
	uint32_t SubnetMask,LocalIP,ReIP;
	if(Re_IP == NULL)
		return false;
	SubnetMask=(MyIP_SubnetMask[0]<<24)|(MyIP_SubnetMask[1]<<16)|(MyIP_SubnetMask[2]<<8)|MyIP_SubnetMask[3];
	LocalIP=(MyIP_LoaclIP[0]<<24)|(MyIP_LoaclIP[1]<<16)|(MyIP_LoaclIP[2]<<8)|MyIP_LoaclIP[3];
	ReIP=(Re_IP[0]<<24)|(Re_IP[1]<<16)|(Re_IP[2]<<8)|Re_IP[3];
	
	LocalIP &= SubnetMask;
	ReIP &= SubnetMask;
	return (LocalIP==ReIP);
}

/**
  * @brief	ARP缓存表读取
  * @param	*ip：  ip地址
  * @param	*OutMAC： 读取到的MAC地址

  * @return	bool	
  * @remark	读取失败返回false
  */
bool ARPCache_Read(const uint8_t *ip,uint8_t *OutMAC)
{
	uint16_t CacheNum = sizeof(ARP_Cache)/sizeof(ARP_Cache[0]);
	const uint8_t *TempIP;
	
	if( (ip==NULL) || (OutMAC==NULL) )
		return false;
	
	if(Is_LAN(ip))
	{
		//是局域网的话，返回原来的IP
		TempIP = ip;
	}
	else
	{
		//是外网的话返回网关IP
		TempIP = MyIP_GateWay;
	}
	
	for(uint16_t i=0;i<CacheNum;i++)
	{
		if(ARP_Cache[i].Flg.reg.ActivFlg == 1)
		{
			if(memcmp(TempIP,ARP_Cache[i].IP,4) == 0)
			{
				memcpy(OutMAC,ARP_Cache[i].MAC,6);
				return true;
			}
		}
	}
	return false;
}

/**
  * @brief	ARP缓存表写入
  * @param	*ip：  ip地址
  * @param	*MAC： MAC地址

  * @return	bool	
  * @remark		
  */
bool ARPCache_Write(const uint8_t *ip,const uint8_t *MAC)
{
	uint16_t CacheNum = sizeof(ARP_Cache)/sizeof(ARP_Cache[0]);
	uint16_t EmptyIndex = 0xFFFF;
	uint32_t MaxTime = ARP_Cache[0].LiveTime;
	uint16_t MaxIndex = 0;
	
	if( (ip==NULL) || (MAC==NULL) )
		return false;
	
	//查找是否已经存在，已经存在的话则替换掉，同时将该记录的时间清0
	for(uint16_t i=0;i<CacheNum;i++)
	{
		if(ARP_Cache[i].Flg.reg.ActivFlg == 1)
		{
			if(ARP_Cache[i].LiveTime > MaxTime)
			{
				MaxTime = ARP_Cache[i].LiveTime;
				MaxIndex = i;
			}
			if(memcmp(ip,ARP_Cache[i].IP,4) == 0)
			{
				memcpy(ARP_Cache[i].MAC,MAC,6);
				
				//检查写入是否正确
				if(memcmp(MAC,ARP_Cache[i].MAC,6) == 0)
				{
					ARP_Cache[i].LiveTime = 0;
					return true;
				}
				return false;
			}
		}
		else
		{
			EmptyIndex = i;						//记录未使用的位置
		}
	}
	
	uint16_t TempIndex;
	//存在未使用的位置
	if(EmptyIndex != 0xFFFF)
	{
		TempIndex = EmptyIndex;
	}
	//全都记录了，替换掉存在时间最长的那一个
	else if(MaxIndex < CacheNum)
	{
		TempIndex = MaxIndex;
	}
	else
	{
		return false;
	}
	//写入缓存
	memcpy(ARP_Cache[TempIndex].IP,ip,4);
	memcpy(ARP_Cache[TempIndex].MAC,MAC,6);
	
	//检查写入是否正确
	if( (memcmp(ip,ARP_Cache[TempIndex].IP,4) == 0) && (memcmp(MAC,ARP_Cache[TempIndex].MAC,6) == 0) )
	{
		ARP_Cache[TempIndex].Flg.reg.ActivFlg = 1;
		ARP_Cache[TempIndex].LiveTime = 0;
		return true;
	}
	else
	{
		return false;
	}
}

/**
  * @brief	ARP缓存表删除
  * @param	*ip：  ip地址

  * @return	bool	
  * @remark		
  */
bool ARPCache_Delete(const uint8_t *ip)
{
	const uint8_t *TempIP;
	uint16_t CacheNum = sizeof(ARP_Cache)/sizeof(ARP_Cache[0]);
	
	if(ip==NULL)
		return false;
	
	if(Is_LAN(ip))
	{
		//是局域网的话，返回原来的IP
		TempIP = ip;
	}
	else
	{
		//是外网的话返回网关IP
		TempIP = MyIP_GateWay;
	}
	
	for(uint16_t i=0;i<CacheNum;i++)
	{
		if(memcmp(TempIP,ARP_Cache[i].IP,4) == 0)
		{
			ARP_Cache[i].Flg.reg.ActivFlg = 0;				//标记为无效即可
			return true;
		}
	}
	return false;
}

/**
  * @brief	ARP缓存表刷新，超过一定时间就重新获取MAC地址
  * @param	void

  * @return	void	
  * @remark		
  */
void MyIP_ARPCacheRefresh(void)
{
	static uint32_t ARP_Time = 0;
	
	//每隔5秒刷新一次ARP缓存
	if(MyIP_GetElapsedTime(ARP_Time) >= 5)
	{
		ARP_Time = MyIP_GetNowTime();
		
		for(uint16_t i=0;i<(uint16_t)(sizeof(ARP_Cache)/sizeof(ARP_Cache[0]));i++)
		{
			if(ARP_Cache[i].Flg.reg.ActivFlg)
			{
				(ARP_Cache[i].LiveTime)++;
				
				//连续6次（30s）没能重新获取MAC地址，删除该ARP缓存
				if(ARP_Cache[i].LiveTime > 5)
				{
					ARP_Cache[i].Flg.reg.ActivFlg = 0;
				}
				else
				{
					ARP_Request(ARP_Cache[i].IP);
				}
			}
		}
	}
}

/**
  * @brief	打印出ARP缓存表
  * @param	void

  * @return	void	
  * @remark		
  */
void ARPCache_Printf(void)
{
	uint16_t CacheNum = sizeof(ARP_Cache)/sizeof(ARP_Cache[0]);
	
	ARP_DEBUGOUT("  IP\t\t\tMAC\t\t\tFlg\tLiveTime\r\n");
	for(uint16_t i=0;i<CacheNum;i++)
	{
		if(ARP_Cache[i].Flg.reg.ActivFlg == 0)
			continue;
		for(uint8_t j=0;j<3;j++)
		{
			ARP_DEBUGOUT("%3d.",ARP_Cache[i].IP[j]);
		}
		ARP_DEBUGOUT("%3d\t\t",ARP_Cache[i].IP[3]);
		
		for(uint8_t j=0;j<5;j++)
		{
			ARP_DEBUGOUT("%02X-",ARP_Cache[i].MAC[j]);
		}
		ARP_DEBUGOUT("%02X\t",ARP_Cache[i].MAC[5]);
		
		ARP_DEBUGOUT("%1d\t%ds\r\n",ARP_Cache[i].Flg.reg.ActivFlg,ARP_Cache[i].LiveTime);
	}
}

/**
  * @brief	ARP打包
  * @param	*node： 连接
  * @param	type： ARP类型，值为1，表示进行ARP请求；值为2，表示进行ARP应答；值为3，表示进行RARP请求；值为4，表示进行RARP应答
  * @param	Lc_MAC: 发送端MAC
  * @param	Lc_IP: 发送端IP
  * @param	Re_MAC: 接收端MAC
  * @param	Re_IP: 接收端IP

  * @return	bool	
  * @remark		
  */
static bool ARP_Head_Pack(LINKSTRUCT *node,uint8_t type,const uint8_t *Lc_MAC,const uint8_t *Lc_IP,const uint8_t *Re_MAC,const uint8_t *Re_IP)
{
	if(node == NULL)
		return false;

	if(type<1 || type>4)
		return false;
	
	if(Lc_MAC==NULL || Lc_IP==NULL || Re_MAC==NULL || Re_IP==NULL)
		return false;

	node->ARP_Head[0] = 0x00;
	node->ARP_Head[1] = 0x01;		//硬件类型，0x0001为以太网

	node->ARP_Head[2] = 0x08;
	node->ARP_Head[3] = 0x00;		//协议地址，0x0800表示为ip

	node->ARP_Head[4] = 0x06;		//硬件地址长度6 表示源和目的物理地址的长度
	node->ARP_Head[5] = 0x04;		//协议地址长度4 表示源和目的的协议地址的长度

	node->ARP_Head[6] = 0x00;		
	node->ARP_Head[7] = type;		//操作：记录该报文的类型，值为1，表示进行ARP请求；值为2，表示进行ARP应答；值为3，表示进行RARP请求；值为4，表示进行RARP应答。

	//发送端MAC
	memcpy(node->ARP_Head+8,Lc_MAC,6);
	//发送端IP
	memcpy(node->ARP_Head+14,Lc_IP,4);
	
	//目的MAC
	memcpy(node->ARP_Head+18,Re_MAC,6);
	//目的端IP
	memcpy(node->ARP_Head+24,Re_IP,4);

	return true;
}

/**
  * @brief	ARP应答
  * @param	*Re_MAC： 目的地MAC
  * @param	*Re_IP： 目的地IP

  * @return	void	
  * @remark		
  */
static void Answer_ARP_Bag(const uint8_t *Re_MAC,const uint8_t *Re_IP)
{
	LINKSTRUCT temp;
	
	if(Re_MAC==NULL || Re_IP==NULL)
		return;
	
	//以太网帧头打包，类型 06 ARP包
	EN_Head_Pack(&temp,Re_MAC,My_MAC,0x06);
	//ARP帧头打包，类型 2 ARP响应
	ARP_Head_Pack(&temp,2,My_MAC,MyIP_LoaclIP,Re_MAC,Re_IP);
	//发送数据包
	ARP_Packet_Send(temp.EN_Head,temp.ARP_Head);

}

//主动发送ARP应答给对方
void Activ_Answer_ARP_Bag(void)
{
	uint8_t Re_MAC[6] = {0x40,0x8d,0x5c,0xb9,0x45,0x3f};
	uint8_t Re_IP[4] = {192,168,1,80};
	
	Answer_ARP_Bag(Re_MAC,Re_IP);
}
/**
  * @brief	发送ARP查询
  * @param	*node： 连接

  * @return	void	
  * @remark		
  */
void ARP_Request(const uint8_t *Re_IP)
{
	if(Re_IP == NULL)
		return;
#if 0	

	//目的地MAC位置，默认为0
//	uint8_t Re_MAC[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t Re_MAC[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	
	//以太网帧头打包，目的MAC为广播MAC,类型 06 ARP包
//	EN_Head_Pack(node,My_MACIP,My_MAC,0x06);
	EN_Head_Pack(&MyNet[0],My_MACIP,My_MAC,0x06);
	
	//ARP帧头打包，类型 1请求
//	if(Is_LAN(node->Re_IP))
//	if(Is_LAN(MyNet[0].Re_IP))	
	if(Is_LAN(Re_IP))	
	{
		//内网
//		ARP_Head_Pack(node,1,My_MAC,MyIP_LoaclIP,Re_MAC,node->Re_IP);
//		ARP_Head_Pack(&MyNet[0],1,My_MAC,MyIP_LoaclIP,Re_MAC,MyNet[0].Re_IP);
		ARP_Head_Pack(&MyNet[0],1,My_MAC,MyIP_LoaclIP,Re_MAC,Re_IP);
	}
	else
	{
		//外网，IP为默认网关,获取路由器的MAC
//		ARP_Head_Pack(node,1,My_MAC,MyIP_LoaclIP,Re_MAC,MyIP_GateWay);
		ARP_Head_Pack(&MyNet[0],1,My_MAC,MyIP_LoaclIP,Re_MAC,MyIP_GateWay);
	}

	//发送数据包
//	ARP_Packet_Send(node->EN_Head,node->ARP_Head);
	ARP_Packet_Send(MyNet[0].EN_Head,MyNet[0].ARP_Head);
	
//	node->Cur_Stat = ARP_REQUEST;
#else
	
	LINKSTRUCT temp;
	//目的地MAC位置，默认为0
	uint8_t Re_MAC[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
	
	//以太网帧头打包，目的MAC为广播MAC,类型 06 ARP包
	EN_Head_Pack(&temp,My_MACIP,My_MAC,0x06);
	
	//ARP帧头打包，类型 1请求
	if(Is_LAN(Re_IP))	
	{
		//内网
		ARP_Head_Pack(&temp,1,My_MAC,MyIP_LoaclIP,Re_MAC,Re_IP);
	}
	else
	{
		//外网，IP为默认网关,获取路由器的MAC
		ARP_Head_Pack(&temp,1,My_MAC,MyIP_LoaclIP,Re_MAC,MyIP_GateWay);
	}

	//发送数据包
	ARP_Packet_Send(temp.EN_Head,temp.ARP_Head);

#endif
}

#if 0
/**
  * @brief	判断当前是谁在ARP
  * @param	*NetIndex: 本地连接序号
  * @param	*Re_ip: 远程IP

  * @return	bool	
  * @remark		
  */
static bool WhoIsInTheARP(uint16_t *NetIndex,const uint8_t *Re_ip)
{
	uint16_t NetNum = sizeof(MyNet)/sizeof(MyNet[0]);
	
	for(uint16_t i=0;i<NetNum;i++)
	{
		if(memcmp(Re_ip,MyNet[i].Re_IP,4) == 0)
		{
			*NetIndex = i;
			return true;
		}
	}
	return false;
}
#endif

/**
  * @brief	ARP数据处理
  * @param	*data: 收到的所有数据，包括EN帧头14位、IP帧头20位
  * @param	len： 收到的所有数据长度，包括EN帧头14位、IP帧头20位

  * @return	void	
  * @remark		
  */
uint8_t ARP_Data_Process(const uint8_t *data,uint16_t len)
{
	if(len < 32)
		return 1;								//ARP报文不完整
	//判断是否是本机IP
	//data+24+14: 目的端的IP起始地址
	if(memcmp(data+24+14,MyIP_LoaclIP,4) != 0)
		return 2;
#if 0
	//打印ARP数据包信息
	ARP_DEBUGOUT("ARP src mac: ");
	for(uint8_t i=0;i<6;i++)
		ARP_DEBUGOUT("%02x ",data[8+i+14]);
	ARP_DEBUGOUT("\r\n");
	ARP_DEBUGOUT("ARP src ip: %d,%d.%d.%d\r\n",data[14+14],data[15+14],data[16+14],data[17+14]);
	
	ARP_DEBUGOUT("ARP dest mac: ");
	for(uint8_t i=0;i<6;i++)
		ARP_DEBUGOUT("%02x ",data[18+i+14]);
	ARP_DEBUGOUT("\r\n");
	ARP_DEBUGOUT("ARP dest ip: %d,%d.%d.%d\r\n",data[24+14],data[25+14],data[26+14],data[27+14]);
	if(data[7+14] == 1)
		ARP_DEBUGOUT("ARP type: request\r\n");
	else if(data[7+14] == 2)
		ARP_DEBUGOUT("ARP type: answer\r\n");
	
	ARP_DEBUGOUT("en head: ");
	for(uint8_t i=0;i<14;i++)
		ARP_DEBUGOUT("%02X ",data[i]);
	ARP_DEBUGOUT("\r\n");
	
	ARP_DEBUGOUT("ARP head: ");
	for(uint8_t i=0;i<28;i++)
		ARP_DEBUGOUT("%02X ",data[i+14]);
	ARP_DEBUGOUT("\r\n\r\n");
#endif
	uint8_t ARP_Type = data[7+14];
	
	//ARP请求
	if(ARP_Type == 1)
	{
		//发送ARP应答
		//data+14+8: 发送端的MAC起始地址
		//data+14+14: 发送端的IP起始地址
		Answer_ARP_Bag(data+14+8,data+14+14);
//		ARP_DEBUGOUT("answer arp: %d.%d.%d.%d\r\n",data[28],data[29],data[30],data[31]);
		
		//保存请求端的IP和MAC到ARP缓存表中
//		ARPCache_Write(data+28,data+22);
	}
	//ARP响应
	//如何判断是那个连接的响应
	//如果能做一个ARP缓存表就好了，就不需要针对每个连接来存放MAC
	//测试中发现向网关发送ARP请求会得到两次响应，第一次返回的MAC无法使用，第二次才是正确的
	else if(ARP_Type == 2)
	{
//		ARP_DEBUGOUT("Get ARP IP: %d.%d.%d.%d\r\n",data[28],data[29],data[30],data[31]);
//		ARP_DEBUGOUT("Get ARP MAC: %02X-%02X-%02X-%02X-%02X-%02X\r\n",data[22],data[23],data[24],data[25],data[26],data[27]);
		
		//将信息写入ARP缓存
		ARPCache_Write(data+28,data+22);
		
		uint16_t NetNum = sizeof(MyNet)/sizeof(MyNet[0]);
		for(uint16_t i=0;i<NetNum;i++)
		{
			if(memcmp(MyNet[i].Re_IP,data+28,4) == 0)
			{
				//IP地址符合
				MyNetConfig_ReMAC(&MyNet[i],data+22);
				MyNet[i].Net_Flg.reg.ARPOK = 1;
			}
			else if( (!Is_LAN(MyNet[i].Re_IP)) && (memcmp(data+28,MyIP_GateWay,4) == 0) )
			{
				//arp到的是网关IP，并且连接的远程ip是外网ip
				MyNetConfig_ReMAC(&MyNet[i],data+22);
				MyNet[i].Net_Flg.reg.ARPOK = 1;
			}
		}
#if 0		
		//查询当前谁在ARP，并且IP符合
		//data+14： 发送方的IP地址
		if(memcmp(data+14+14,MyIP_GateWay,4) == 0)	//如果为网关IP
		{
			uint16_t NetNum = sizeof(MyNet)/sizeof(MyNet[0]);
			for(uint16_t i=0;i<NetNum;i++)
			{
//				if(MyNet[i].Net_Type & CLIENT)		//如果为客户端
//				{
//					if(!Is_LAN(&MyNet[i]))			//如果是外网
					if(!Is_LAN(MyNet[i].Re_IP))			//如果是外网
					{
						//实际测试路由器会返回两次，说明局域网内有网卡在冒充网关，该网卡MAC 48-7D-2E-04-28-36
						//第二次返回才是对的MAC
						//所以此处不判断当前状态了
//						if(MyNet[i].Cur_Stat == ARP_REQUEST)	//且正在ARP，则改为ARP_ANSWER，多个连接是外网时，只需要一次ARP
//						{
							//复制远程MAC到连接0
							MyNetConfig_ReMAC(&MyNet[i],data+14+8);
//							MyNet[i].Cur_Stat = ARP_ANSWER;		//ARP结束
//							MyNet[i].Net_Flg.reg.ARPOK = 1;		//ARP成功
							MyNet[i].Net_Flg.ARPOK = 1;		//ARP成功
							ARP_DEBUGOUT("Get ARP MAC(%d): %02X-%02X-%02X-%02X-%02X-%02X\r\n",i,data[22],data[23],data[24],data[25],data[26],data[27]);
							break;
//						}
					}
//				}
			}
		}
		else
		{
			//收到对方的ARP应答后要确定是哪个连接在查询对方ARP，再将对方MAC存如哪个连接
			//检查所有连接，将对方MAC存入IP地址相同的连接当中
			uint16_t NetIndex;
			
			if(!WhoIsInTheARP(&NetIndex,(data+28)))
				return 3;										//没人在发ARP查询报文

			//如果是正在进行ARP，则结束当前连接的ARP
//			if(MyNet[NetIndex].Cur_Stat == ARP_REQUEST)
//			{
				MyNet[NetIndex].Net_Flg.ARPOK = 1;		//ARP成功
//				MyNet[NetIndex].Cur_Stat = ARP_ANSWER;
				MyNetConfig_ReMAC(&MyNet[NetIndex],data+14+8);
				
				ARP_DEBUGOUT("get mac\r\n");
//			}
		}
#endif
	}
	//RARP请求
	else if(ARP_Type == 3)
	{
	}
	//RARP响应
	else if(ARP_Type == 4)
	{
	}
	else
	{
//		ARP_DEBUGOUT("error arp type: 0x%02X",ARP_Type);
	}
	return 0;
}
