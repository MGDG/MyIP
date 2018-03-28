/**
  ******************************************************************************
  * @file    MyIP_IP.c
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   IP数据包打包
  ******************************************************************************
 **/
#include "MyIP_IP.h"
#include "MyIP_ICMP.h"
#include "MyIP_UDP.h"
#include "MyIP_TCP.h"

#define IP_DEBUGOUT(...)	TCPDEBUGOUT(__VA_ARGS__)
/**
  * @brief	IP 首部填充
  * @param	*node：连接
  * @param	IP_Type：IP数据报类型0 UDP,1 TCP,2 ICMP
  * @param	IP_len：IP数据报长度(IP首部+TCP或UDP或ICMP首部+数据),20+8+UDP_len,20+20+TCP_Len,20+ICMP_Len,

  * @return	bool	
  * @remark		
  */
bool IP_Head_Pack(LINKSTRUCT *node,const uint8_t *Re_IP,uint8_t IP_Type,uint16_t IP_len)
{
	if(node == NULL)
		return false;

	//IP 首部填充  20字节
	node->IP_Head[0] = 0x45;			//版本 首部长度
	node->IP_Head[1]=0;					//服务类型 一般服务
	node->IP_Head[2]=IP_len>>8;
	node->IP_Head[3]=IP_len;

	node->IP_Mark++;//标示字段+1，唯一字段
	if(node->IP_Mark==0xffff)
		node->IP_Mark=0x1200;	//如果为最大值，则从0x1200开始重新记数
	node->IP_Head[4]=node->IP_Mark>>8;
	node->IP_Head[5]=node->IP_Mark;

	node->IP_Head[6]=0x40;		//0;
	node->IP_Head[7]=0;					//标志，偏移，分片
	node->IP_Head[8]=node->IP_TTL;		//生存周期

	if(IP_Type == 0)
		node->IP_Head[9]=0x11;			//17 UDP数据包
	else if(IP_Type == 1)
		node->IP_Head[9]=0x06;			//6 TCP数据包
	else
		node->IP_Head[9]=0x01;			//01 ICMP

	node->IP_Head[10]=0;
	node->IP_Head[11]=0;				//检验和

	memcpy(node->IP_Head+12,MyIP_LoaclIP,4);		//填充本地IP
//	memcpy(node->IP_Head+16,node->Re_IP,4);		//填充目的IP
	memcpy(node->IP_Head+16,Re_IP,4);		//填充目的IP


	//计算IP首部检验和
	uint32_t sum = MyIP_CheckSum((uint16_t *)(node->IP_Head),20);//IP头20;
	uint16_t tem = MyIP_CheckCode(sum);//计算溢出位

//	node->IP_Head[10]=tem>>8;
//	node->IP_Head[11]=tem;

	node->IP_Head[10]=tem;
	node->IP_Head[11]=tem>>8;

	return true;
}


/**
  * @brief	IP首部组包（回Ping专用）
  * @param	*data: 收到的所有数据，包括EN帧头14位、IP帧头20位
  * @param	IP_len:  IP帧头长度位

  * @return	bool	
  * @remark		
  */
bool IP_Head_Pack_Ping(LINKSTRUCT *node,uint16_t IP_len,const uint8_t *data)
{
	if(node == NULL)
		return false;

	//IP 首部填充  20字节
	node->IP_Head[0] = 0x45;			//版本 首部长度
	node->IP_Head[1]=0;					//服务类型 一般服务
	node->IP_Head[2]=IP_len>>8;
	node->IP_Head[3]=IP_len;

	node->IP_Mark++;//标示字段+1，唯一字段
	if(node->IP_Mark==0xffff)
		node->IP_Mark=0x1200;	//如果为最大值，则从0x1200开始重新记数
	
	node->IP_Head[4]=data[18];
	node->IP_Head[5]=data[19];	//回Ping IP包的标志字段要跟 ping请求 IP包的标志字段一致

	node->IP_Head[6]=0;
	node->IP_Head[7]=0;					//标志，偏移，分片
	node->IP_Head[8]=data[22];			//node->IP_TTL;		//生存周期

	node->IP_Head[9]=0x01;				//01 ICMP

	node->IP_Head[10]=0;
	node->IP_Head[11]=0;				//检验和

	memcpy(node->IP_Head+12,MyIP_LoaclIP,4);		//填充本地IP
	memcpy(node->IP_Head+16,data+26,4);			//填充目的IP


	//计算IP首部检验和
	uint32_t sum = MyIP_CheckSum((uint16_t *)(node->IP_Head),20);//IP头20;
	uint16_t tem = MyIP_CheckCode(sum);//计算溢出位

	//注意字节调换
	node->IP_Head[10]=tem;
	node->IP_Head[11]=tem>>8;

	return true;
}


/**
  * @brief	IP 数据包处理
  * @param	*data: 收到的完整数据包，EN+IP+其他
  * @param	len: 数据包的长度

  * @return	void	
  * @remark		
  */
uint8_t IP_Data_Process(const uint8_t *data,uint16_t len)
{
	uint8_t macFlg = 0,ipFlg = 0;
	
	if(len < 34)
	{
		//14以太网头 + 20IP头
		IP_DEBUGOUT("IP bag len error");
		return 1;										//IP报文不完整
	}
	
	if(memcmp(data,My_MAC,6) == 0)						//判断MAC地址是否符合
	{
		macFlg = 1;
	}
	else if(memcmp(data,My_MACIP,6) == 0)				//判断是否是广播地址
	{
		macFlg = 2;
	}
	
	if(memcmp(data+30,MyIP_LoaclIP,4) == 0)				//判断IP地址是否符合
	{
		ipFlg = 1;
	}
	
	//IP检验和检验
	uint8_t temp_IP_Head[20];
	memcpy(temp_IP_Head,data+14,20);
	temp_IP_Head[10] = 0;
	temp_IP_Head[11] = 0;
	uint32_t sum = MyIP_CheckSum((uint16_t *)temp_IP_Head,20);		//IP头20;
	uint16_t tem = MyIP_CheckCode(sum);								//计算溢出位
	if((data[24] != (uint8_t)tem) || data[25] != (uint8_t)(tem>>8))
	{
		IP_DEBUGOUT("IP check sum error\r\n");
		return 2;
	}

	//是本机包，或广播包
	if(macFlg || ipFlg)
	{
		//判断IP数据包的协议字段
		//1： ICMP
		//6： TCP
		//17： UDP
		if(0x01 == data[23])			//1 ICMP
		{
			if(macFlg == 1 && ipFlg == 1)
			{
				return ICMP_Data_Process(data,len);
			}
		}
		else if(0x11 == data[23])		//17 UDP数据包
		{
			return UDP_Data_Process(data,len);
		}
		else if(0x06 == data[23])		//6 TCP数据包
		{
			return TCP_Data_Process(data,len);
		}
	}
	return 0;
}
