/**
  ******************************************************************************
  * @file    MyIP_UDP.c
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   UDP数据包打包
  ******************************************************************************
 **/
#include "MyIP_UDP.h"
#include "MyIP_Enthernet.h"
#include "MyIP_IP.h"
#include "MyIP_DHCP.h"

#define UDP_DEBUGOUT(...)	TCPDEBUGOUT(__VA_ARGS__)

/*
server:	socket-->bind-->recvfrom-->sendto-->close
client: socket-->sendto-->revcfrom-->close

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
              const struct sockaddr *dest_addr, socklen_t addrlen);
第一个参数sockfd:正在监听端口的套接口文件描述符，通过socket获得
第二个参数buf：发送缓冲区，往往是使用者定义的数组，该数组装有要发送的数据
第三个参数len:发送缓冲区的大小，单位是字节
第四个参数flags:填0即可
第五个参数dest_addr:指向接收数据的主机地址信息的结构体，也就是该参数指定数据要发送到哪个主机哪个进程
第六个参数addrlen:表示第五个参数所指向内容的长度
返回值：成功：返回发送成功的数据长度
       失败： -1

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                struct sockaddr *src_addr, socklen_t *addrlen);
第一个参数sockfd:正在监听端口的套接口文件描述符，通过socket获得
第二个参数buf：接收缓冲区，往往是使用者定义的数组，该数组装有接收到的数据
第三个参数len:接收缓冲区的大小，单位是字节
第四个参数flags:填0即可
第五个参数src_addr:指向发送数据的主机地址信息的结构体，也就是我们可以从该参数获取到数据是谁发出的
第六个参数addrlen:表示第五个参数所指向内容的长度
返回值：成功：返回接收成功的数据长度
       失败： -1
	   
int bind(int sockfd, const struct sockaddr* my_addr, socklen_t addrlen);
第一个参数sockfd:正在监听端口的套接口文件描述符，通过socket获得
第二个参数my_addr:需要绑定的IP和端口
第三个参数addrlen：my_addr的结构体的大小
返回值：成功：0
       失败：-1
*/

/**
  * @brief	校验接收到的UDP数据包
  * @param	*data：数据(收到的原始UDP数据包，包含EN头 IP头 UDP头)
  * @param	len：数据长度

  * @return	bool	
  * @remark		
  */
static bool UDP_Data_Check(const uint8_t *data,uint16_t len)
{
	uint8_t UDP_False[12];
	uint8_t UDP_Head[8];
	
	if(data == NULL)
		return false;
	
	if(len < 42)
		return false;						//小于最小UDP数据包长度
	
	//填充UDP伪头部
	memcpy(UDP_False,data+26,8);			//填充IP
	UDP_False[8] = 0;
	UDP_False[9] = 17;						//协议
	UDP_False[10] = data[38];				//UDP首部长+数据长
	UDP_False[11] = data[39];				//UDP首部长+数据长
	
	
	//填充UDP头部
	memcpy(UDP_Head,data+34,8);
	
	//获取接收到的校验和
	uint16_t GetSum =  (((uint16_t)(UDP_Head[7]<<8))|UDP_Head[6]);
		
	UDP_Head[6]=0;
	UDP_Head[7]=0;							//检验和稍后补充
	
	//计算数据部分的长度
	uint16_t UDP_Data_Len = (((uint16_t)(data[38]<<8))|data[39])-8;
	
	//计算校验和
	uint32_t sum = TCPIP_Check_Sum((uint16_t *)(UDP_False),12);		//UDP伪首部12
	sum += TCPIP_Check_Sum((uint16_t *)(UDP_Head),8);				//UDP首部8
	sum += TCPIP_Check_Sum((uint16_t *)(&data[42]),UDP_Data_Len);	//数据部分，偏移指针14+20+8
	uint16_t tem = TCPIP_Check_Code(sum);
	
	return (tem == GetSum);
}

/**
  * @brief	UDP 首部填充
  * @param	*node：连接
  * @param	*data：数据
  * @param	len：数据长度

  * @return	bool	
  * @remark		
  */
static bool UDP_Head_Pack(LINKSTRUCT *node,const UDPSTRUCT *udp,const uint8_t *data,uint16_t len)
{
	uint8_t UDP_False[12];
	
	if( (node==NULL) || (UDP_False==NULL) || (data==NULL) || (len==0) )
		return false;
	
	//UDP伪首部填充 12字节
	memcpy(UDP_False,MyIP_LoaclIP,4);			//填充本地IP
//	memcpy(UDP_False+4,node->Re_IP,4);		//填充目的IP
	memcpy(UDP_False+4,udp->Re_IP,4);		//填充目的IP
	UDP_False[8] = 0;
	UDP_False[9] = 17;						//协议
	UDP_False[10] = (8+len)>>8;				//UDP首部长+数据长
	UDP_False[11] = (8+len);					//UDP首部长+数据长


	//UDP 首部填充  8字节
//	node->UDP_Head[0]=node->Lc_Port>>8;
//	node->UDP_Head[1]=node->Lc_Port;				//填充本地端口
//	node->UDP_Head[2]=node->Re_Port>>8;
//	node->UDP_Head[3]=node->Re_Port;				//填充目的端口
	node->UDP_Head[0]=udp->Lc_Port>>8;
	node->UDP_Head[1]=udp->Lc_Port;				//填充本地端口
	node->UDP_Head[2]=udp->Re_Port>>8;
	node->UDP_Head[3]=udp->Re_Port;				//填充目的端口
	node->UDP_Head[4]=(len+8)>>8;
	node->UDP_Head[5]=(len+8);						//UDP长度=UDP首部+数据
	node->UDP_Head[6]=0;
	node->UDP_Head[7]=0;							//检验和稍后补充


	//计算检验和
	uint32_t sum = TCPIP_Check_Sum((uint16_t *)(UDP_False),12);		//TCP伪首部12
	sum += TCPIP_Check_Sum((uint16_t *)(node->UDP_Head),8);				//TCP首部20
	sum += TCPIP_Check_Sum((uint16_t *)data,len);							//TCP首部20
	uint16_t tem = TCPIP_Check_Code(sum);									//计算溢出位

	node->UDP_Head[6]=tem;
	node->UDP_Head[7]=tem>>8;							//检验和稍后补充

	return true;
}


/**
  * @brief	发送UDP数据包
  * @param	*node: 连接
  * @param	*data：数据
  * @param	len：数据长度

  * @return	bool	
  * @remark	发送ping之前需要知道对方的MAC地址，如果MAC地址为空则需要ARP
  */
uint8_t Send_UDP_Bag(LINKSTRUCT *node,const UDPSTRUCT *udp,const uint8_t *data,uint16_t len)
{
	if(node == NULL || data ==NULL)
		return 1;	

	//以太网帧头打包，类型 0 IP类型
//	if(!EN_Head_Pack(node,node->Re_MAC,My_MAC,0x00))
	if(!EN_Head_Pack(node,udp->Re_MAC,My_MAC,0x00))
		return 2;

	//IP帧头打包,IP数据报类型0 UDP
	//IP_len : IP首部20+UDP首部8+数据len
	if(!IP_Head_Pack(node,udp->Re_IP,0,28+len))
		return 3;

	//UDP帧头打包
	if(!UDP_Head_Pack(node,udp,data,len))
		return 4;

	//发送UDP数据包
	UDP_Packet_Send(node->EN_Head,node->IP_Head,node->UDP_Head,data,len);
	return 0;
}

void UDP_Config(LINKSTRUCT *node,const uint8_t *Re_IP,uint16_t Re_PORT,uint16_t Lc_PORT)
{
	if(node == NULL || Re_IP == NULL)
		return;	

	memcpy(node->Re_IP,Re_IP,4);
	node->Re_Port = Re_PORT;
	node->Lc_Port = Lc_PORT;
}

uint8_t UDP_Data_Process(const uint8_t *data,uint16_t len)
{
	if(!UDP_Data_Check(data,len))
		return 1;
	
	uint16_t RPort=(data[34]<<8)|data[35];				//远程端口,等于67的话为DHCP包
	uint16_t LPort=(data[36]<<8)|data[37];				//本地端口
	uint16_t LinkIndex;
	
#if 0	
	else
		UDP_DEBUGOUT("udp sum check ok\r\n");
	
	UDP_DEBUGOUT("recev udp bag,net:%d,RPort:%d,LPort:%d\r\n",LinkIndex,RPort,LPort);
	UDP_DEBUGOUT("en head: ");
	for(uint8_t i=0;i<14;i++)
		UDP_DEBUGOUT("%02X ",data[i]);
	UDP_DEBUGOUT("\r\n");
	
	UDP_DEBUGOUT("ip head: ");
	for(uint8_t i=0;i<20;i++)
		UDP_DEBUGOUT("%02X ",data[i+14]);
	UDP_DEBUGOUT("\r\n");
	
	UDP_DEBUGOUT("udp head: ");
	for(uint8_t i=0;i<8;i++)
		UDP_DEBUGOUT("%02X ",data[i+34]);
	UDP_DEBUGOUT("\r\n");
	
	uint16_t datalen = (((uint16_t)(data[16]<<8))|data[17])-28;		//总长度,减去20IP头和8UDP头
	UDP_DEBUGOUT("udp data(%d): ",datalen);
	for(uint8_t i=0;i<datalen;i++)
		UDP_DEBUGOUT("%02X ",data[i+42]);
	UDP_DEBUGOUT("\r\n");
	
#endif

	if(RPort==67 && LPort==68)
	{
		//该数据包为DHCP
		return DHCP_Data_Process(data,len);
	}

	if(!TCPIP_Check_Socket((UDP_CLIENT|UDP_SERVER),LPort,&LinkIndex))
	{
//		UDP_DEBUGOUT("local port not found\r\n");
		return 2;
	}
	
	//实际数据长度
	uint16_t datalen = (((uint16_t)(data[16]<<8))|data[17])-28;	
	
	//实际数据从data+42开始，长度为DataLen
	UDP_Data_Recev(LinkIndex,data+42,datalen);

	return 0;
}

void UDP_Send(LINKSTRUCT *node,const uint8_t *ip,uint16_t RePort,const uint8_t *data,uint16_t len)
{
	//配置连接参数
	UDPSTRUCT tempUdp;
	memcpy(tempUdp.Re_IP,ip,4);						//远程IP
	memcpy(tempUdp.Re_MAC,MyNet[0].Re_MAC,6);		//远程MAC，此处假设已经通过ARP获得了远程的MAC地址
	tempUdp.Lc_Port = node->Lc_Port;							//本地端口，默认使用1234
	tempUdp.Re_Port = RePort;						//远程端口
	
	Send_UDP_Bag(node,&tempUdp,data,len);
}
