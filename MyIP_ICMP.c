/**
  ******************************************************************************
  * @file    MyIP_ICMP.c
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   
  ******************************************************************************
 **/
#include "MyIP_ICMP.h"
#include "MyIP_Enthernet.h"
#include "MyIP_IP.h"
#include "MyIP_ARP.h"

#define ICMP_DEBUGOUT(...)	TCPDEBUGOUT(__VA_ARGS__)

/**
  * @brief	发送ICMP_Ping回包
  * @param	*data: 收到的ICMP数据包
  * @param	len： ICMP数据包的长度
  * @param	ICMP_Type: 类型
  * @param	ICMP_Code： 代码

  * @return	bool	
  * @remark		
  */
static bool ICMP_Head_Pack(LINKSTRUCT *node,const uint8_t *data,uint16_t len,uint8_t ICMP_Type,uint8_t ICMP_Code)
{
	static uint8_t PingSeq = 0;
	
	if(node == NULL)
		return false;
	if(len > 40)
		return false;
	
	//回应ping请求的话，直接复制收到的ICMP报文内容
	if(ICMP_Type == 0)
	{
		memcpy(node->ICMP_Data,data,len);
	}
	//如果是发送ping request,则Sequence number要递增
	else if(ICMP_Type == 8)
	{
		PingSeq++;
		node->ICMP_Data[4]=0x01;
		node->ICMP_Data[5]=0x00;
		node->ICMP_Data[6]=PingSeq>>8;
		node->ICMP_Data[7]=(uint8_t)PingSeq;
		
		node->ICMP_Data[8] = 0x61;
		for(uint8_t i=9;i<40;i++)
		{
			//填充字母，从a到w，再从a开始，填满32个
			node->ICMP_Data[i] = node->ICMP_Data[i-1]+1;
			if(node->ICMP_Data[i] >= 0x78)
				node->ICMP_Data[i] = 0x61;
		}
	}
	
	node->ICMP_Data[0]=ICMP_Type;//类型
	node->ICMP_Data[1]=ICMP_Code;//代码
	node->ICMP_Data[2]=0;
	node->ICMP_Data[3]=0;//检验和
	
	//计算检验和
	uint32_t sum = TCPIP_Check_Sum((uint16_t *)(node->ICMP_Data),40);
	uint16_t tem = TCPIP_Check_Code(sum);
	
//	node->ICMP_Data[2]=tem>>8;
//	node->ICMP_Data[3]=(uint8_t)tem;//检验和稍后补充
	
	node->ICMP_Data[2]=tem;
	node->ICMP_Data[3]=tem>>8;//检验和稍后补充
	
	return true;
}


/**
  * @brief	发送ICMP_Ping回包
  * @param	*data: 收到的所有数据，包括EN帧头14位、IP帧头20位
  * @param	len： 收到的所有数据长度，包括EN帧头14位、IP帧头20位

  * @return	bool	
  * @remark		
  */
static uint8_t Send_ICMP_Ping_Back_Bag(LINKSTRUCT *node,const uint8_t *data,uint16_t len)
{
	if(node == NULL)
		return 1;	
	
	if(len < 34 || len>(34+40))
		return 2;			//小于最小数据包长度,或者ICMP包头部分长度大于ICMP数组的长度，定义的ICMP数据数组只有40个

	//以太网帧头打包，类型 0 IP类型
	if(!EN_Head_Pack(node,data+6,My_MAC,0x00))
		return 3;
	
	//组ICMP_Ping包
	//回显，ICMP类型0代码0：回显应答（ping应答）
	if(!ICMP_Head_Pack(node,data+34,len-34,0,0))
		return 4;
	
	//组IP头
	//IP包总长度位：len - 14为以太网帧头位
	if(!IP_Head_Pack_Ping(node,len-14,data))
		return 5;
	
	
	//发送ICMP_Ping回包
	ICMP_Ping_Packet_Send(node->EN_Head,node->IP_Head,node->ICMP_Data,len-34);

#if 0	
	ICMP_DEBUGOUT("en head: ");
	for(uint8_t i=0;i<14;i++)
		ICMP_DEBUGOUT("%02X ",node->EN_Head[i]);
	ICMP_DEBUGOUT("\r\n");
	
	ICMP_DEBUGOUT("ip head: ");
	for(uint8_t i=0;i<20;i++)
		ICMP_DEBUGOUT("%02X ",node->IP_Head[i]);
	ICMP_DEBUGOUT("\r\n");
	
	ICMP_DEBUGOUT("icmp head: ");
	for(uint8_t i=0;i<len-34;i++)
		ICMP_DEBUGOUT("%02X ",node->ICMP_Data[i]);
	ICMP_DEBUGOUT("\r\n");
#endif

	return 0;
}

/**
  * @brief	发送ICMP_Ping
  * @param	*node: 连接
  * @param	Re_IP: 对方IP地址

  * @return	bool	
  * @remark	发送ping之前需要知道对方的MAC地址，如果MAC地址为空则需要ARP
  */
uint8_t Send_Ping_Bag(const uint8_t *Re_IP,const uint8_t *Re_MAC)
{
	LINKSTRUCT temp;
	if(Re_MAC == NULL || Re_IP == NULL)
		return 1;	
	
	//以太网帧头打包，类型 0 IP类型
	if(!EN_Head_Pack(&temp,Re_MAC,My_MAC,0x00))
		return 2;
	
	//组ICMP_Ping request包
	//回显，ICMP类型8代码0：请求应答（ping请求）
	if(!ICMP_Head_Pack(&temp,NULL,0,8,0))
		return 3;
	
	//组IP头
	temp.IP_TTL = 128;
	if(!IP_Head_Pack(&temp,Re_IP,2,60))
		return 4;
	
	//发送ICMP_Ping包
	ICMP_Ping_Packet_Send(temp.EN_Head,temp.IP_Head,temp.ICMP_Data,40);
	
	return 0;
}


/**
  * @brief	ICMP数据处理
  * @param	*data: 收到的所有数据，包括EN帧头14位、IP帧头20位
  * @param	len： 收到的所有数据长度，包括EN帧头14位、IP帧头20位

  * @return	bool	
  * @remark		
  */
uint8_t ICMP_Data_Process(const uint8_t *data,uint16_t len)
{
	if(data == NULL)
		return 1;
	
	uint8_t ICMP_Type = data[0+34];
	uint8_t ICMP_Code = data[1+34];

#if 0	
	ICMP_DEBUGOUT("ICMP type: %02X\r\n",ICMP_Type);
	ICMP_DEBUGOUT("ICMP code: %02X\r\n",ICMP_Code);
	
	ICMP_DEBUGOUT("en head: ");
	for(uint8_t i=0;i<14;i++)
		ICMP_DEBUGOUT("%02X ",data[i]);
	ICMP_DEBUGOUT("\r\n");
	
	ICMP_DEBUGOUT("ip head: ");
	for(uint8_t i=0;i<20;i++)
		ICMP_DEBUGOUT("%02X ",data[i+14]);
	ICMP_DEBUGOUT("\r\n");
	
	ICMP_DEBUGOUT("icmp head: ");
	for(uint8_t i=0;i<len-34;i++)
		ICMP_DEBUGOUT("%02X ",data[i+34]);
	ICMP_DEBUGOUT("\r\n\r\n");
#endif

	//请求回显
	if(ICMP_Type==0x08 && ICMP_Code==0x00)
	{
		//将收到的ICMP数据包发回去
//		ICMP_DEBUGOUT("recev ping request\r\n");
//		ICMP_DEBUGOUT("ping bag len: %d\r\n",len);

#if 0		
		ICMP_DEBUGOUT("en head: ");
		for(uint8_t i=0;i<14;i++)
			ICMP_DEBUGOUT("%02X ",data[i]);
		ICMP_DEBUGOUT("\r\n");
		
		ICMP_DEBUGOUT("ip head: ");
		for(uint8_t i=0;i<20;i++)
			ICMP_DEBUGOUT("%02X ",data[i+14]);
		ICMP_DEBUGOUT("\r\n");
		
		ICMP_DEBUGOUT("icmp head: ");
		for(uint8_t i=0;i<len-34;i++)
			ICMP_DEBUGOUT("%02X ",data[i+34]);
		ICMP_DEBUGOUT("\r\n\r\n");
#endif

#if 0		
		//打印出校验和对比看是否正确
		uint8_t temp[40];
		memcpy(temp,data+34,40);
		temp[2] = 0;
		temp[3] = 0;
		uint32_t sum = TCPIP_Check_Sum((uint16_t *)temp,40);//累加总和
		uint16_t tem = TCPIP_Check_Code(sum);
		temp[2]=tem;
		temp[3]=tem>>8;//检验和稍后补充
		ICMP_DEBUGOUT("%02X %02X\r\n",temp[2],temp[3]);
#endif		
		
		return Send_ICMP_Ping_Back_Bag(&MyNet[0],data,len);
	}
	
	//回显应答
	else if(ICMP_Type==0x00 && ICMP_Code==0x00)
	{
//		uint16_t NetNum = sizeof(MyNet)/sizeof(MyNet[0]);
//		for(uint16_t i=0;i<NetNum;i++)
//		{
//			//对比MAC地址，
//		}
		ICMP_DEBUGOUT("ping ok\r\n");
		return 0;
	}
	return 2;
}

void MyIP_Ping(const uint8_t *Re_IP)
{
	uint8_t MAC[6];
	//检查ARP缓存中是否存在对方MAC
	if(ARPCache_Read(Re_IP,MAC))
	{
		Send_Ping_Bag(Re_IP,MAC);
		ICMP_DEBUGOUT("ping MAC: %02X-%02X-%02X-%02X-%02X-%02X\r\n",MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5]);
	}
	else
	{
		//先发ARP获取对方MAC
		ARP_Request(Re_IP);
		//状态机里等待ARP完成并发送PING
		ICMP_DEBUGOUT("MAC not found\r\n");
	}
}
