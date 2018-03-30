/**
  ******************************************************************************
  * @file    MyIP_TCP.c
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   TCP数据包打包
  ******************************************************************************
 **/
#include "MyIP_TCP.h"
#include "MyIP_Enthernet.h"
#include "MyIP_IP.h"
#include "MyIP_ARP.h"

#define TCP_DEBUGOUT(...)	TCPDEBUGOUT(__VA_ARGS__)

/**
  * @brief	校验接收到的TCP数据包
  * @param	*data：数据(收到的原始TCP数据包，包含EN头 IP头 TCP头)
  * @param	len：数据长度
  * @param	*ValidDataIndex: 有效用户数据的起始位置
  * @param	*ValidDataLen: 有效用户数据的长度
  * @param	*TCPFlg: TCP标志位
  * @param	*L_Port: 本地端口
  * @param	*R_Port: 目的端口

  * @return	bool	
  * @remark		
  */
static bool TCP_Data_Check(const uint8_t *data,uint16_t len,
						  uint16_t *ValidDataIndex,uint16_t *ValidDataLen,
						  uint8_t *TCPFlg,uint16_t *L_Port,uint16_t *R_Port,
						  uint32_t *TCP_Mark,uint32_t *TCP_CMark)
{
	uint8_t TCP_False[12];
	uint8_t TCP_Head[60];			//TCP首部长度最小20，最大60，由TCP_Head[12]的高4位表示
	uint16_t datalen;
	uint8_t TCP_Head_Len;
	
	if(data == NULL)
		return false;

	if(len < 54)
		return false;						//小于最小TCP数据包长度	

	//TCP伪首部填充 12字节
	memcpy(TCP_False,data+26,8);			//填充IP
	TCP_False[8] = 0;
	TCP_False[9] = 6;							//6 TCP
	datalen =  (((uint16_t)(data[16]<<8))|data[17]);	//IP帧头中的总长度位
	TCP_Head_Len = (data[46]>>2) & 0x3C;// 0x60;		//偏移位置14+20+12				// ((data[46]>>4) & 0x0F) * 4;
	if(TCP_Head_Len < 20)
		return false;							//TCP帧头最小长度 20
	if(datalen < TCP_Head_Len+20)
		return false;							//小于最小TCP数据包长度(20IP头+20TCP头)
	datalen -= 20;								//减去IP头部的长，剩余TCP帧头长度+数据长度
	TCP_False[10] = datalen>>8;					//TCP首部长+数据长
	TCP_False[11] = datalen;					//TCP首部长+数据长

	//TCP 首部填充  20字节
	memcpy(TCP_Head,data+34,TCP_Head_Len);		//偏移 34 字节，14以太网帧头+20IP帧头

	//获取接收到的校验和
	uint16_t GetSum =  (((uint16_t)(TCP_Head[17]<<8))|TCP_Head[16]);
	TCP_Head[16] = 0;						//检验和清除
	TCP_Head[17] = 0;						//检验和清除

	//计算数据部分的长度
	datalen -= TCP_Head_Len;							//减去TCP帧头的长度
	
	//计算校验和
	uint32_t sum = MyIP_CheckSum((uint16_t *)(TCP_False),12);		//TCP伪首部12
	sum += MyIP_CheckSum((uint16_t *)(TCP_Head),TCP_Head_Len);	//TCP首部 TCP_Head_Len
	sum += MyIP_CheckSum((uint16_t *)(data+34+TCP_Head_Len),datalen);			//数据部分，偏移指针14+20+TCP_Head_Len
	uint16_t tem = MyIP_CheckCode(sum);
	
	if(tem == GetSum)
	{
		*ValidDataIndex = 34+TCP_Head_Len;					//有效用户数据在完整数据包中的起始位置
		*ValidDataLen = datalen;							//有效用户数据的长度
		*TCPFlg = data[47];
		*L_Port = ((uint16_t)(data[36])<<8)|data[37];
		*R_Port = (data[34]<<8)|data[35];
		*TCP_Mark = (data[38]<<24) | (data[39]<<16) | (data[40]<<8) | data[41];
		*TCP_CMark = (data[42]<<24) | (data[43]<<16) | (data[44]<<8) | data[45];
		return true;
	}
	return false;
}

/**
  * @brief	TCP 首部填充
  * @param	*node：连接
  * @param	Buf_Len：数据缓冲区大小，最少要在308字节，否则不能DHCP动态获取IP
  * @param	*data：数据
  * @param	len：数据长度

  * @return	bool	
  * @remark		
  */
static bool TCP_Head_Pack(LINKSTRUCT *node,uint8_t TCP_Flag,uint16_t Buf_Len,const uint8_t *data,uint16_t len)
{
	uint8_t TCP_False[12];				//TCP协议伪首部 [12]
	if( (node==NULL) || (TCP_False==NULL) )
		return false;

	if(data == NULL && len != 0)
		return false;

	//TCP伪首部填充 12字节
	memcpy(TCP_False,MyIP_LoaclIP,4);			//填充本地IP
	memcpy(TCP_False+4,node->Re_IP,4);			//填充目的IP
	TCP_False[8] = 0;
	TCP_False[9] = 6;							//6 TCP


	uint16_t head_len;
	if( (TCP_Flag==TCPFLG_SYN) || (TCP_Flag==(TCPFLG_SYN|TCPFLG_ACK)) )
		head_len = 32+len;						//还有12个TCP选项字节
	else
		head_len = 20+len;
	
	TCP_False[10] = (head_len)>>8;				//TCP首部长+数据长
	TCP_False[11] = (uint8_t)head_len;			//TCP首部长+数据长

	//TCP 首部填充  20字节
	node->TCP_Head[0] = node->Lc_Port>>8;
	node->TCP_Head[1] = node->Lc_Port;			//填充本地端口
	node->TCP_Head[2] = node->Re_Port>>8;
	node->TCP_Head[3] = node->Re_Port;			//填充目的端口
	node->TCP_Head[4] = node->TCP_Mark>>24;
	node->TCP_Head[5] = node->TCP_Mark>>16;
	node->TCP_Head[6] = node->TCP_Mark>>8;
	node->TCP_Head[7] = node->TCP_Mark;			//填充TCP序号
	node->TCP_Head[8] = node->TCP_CMark>>24;
	node->TCP_Head[9] = node->TCP_CMark>>16;
	node->TCP_Head[10] = node->TCP_CMark>>8;
	node->TCP_Head[11] = node->TCP_CMark;		//填充TCP确认序号
	
	//如果是向对方发送连接请求的话，还要带上Options字段
	if( (TCP_Flag==TCPFLG_SYN) || (TCP_Flag==(TCPFLG_SYN|TCPFLG_ACK)) )
		node->TCP_Head[12] = 0x80;				//首部长为32，附加了12位选项字段
	else
		node->TCP_Head[12] = 0x50;				//TCP首部长20

	node->TCP_Head[13] = TCP_Flag;				//TCP6个位标志
	node->TCP_Head[14] = (Buf_Len-58)>>8;
	node->TCP_Head[15] = (Buf_Len-58);			//TCP窗口大小，最大能收的TCP数据，接收缓冲区的大小-14-20-20-4
	node->TCP_Head[16] = 0;						//检验和
	node->TCP_Head[17] = 0;						//检验和
	node->TCP_Head[18] = 0;
	node->TCP_Head[19] = 0;						//紧急指针
	
	if( (node->TCP_Head[12]) != 0x50)
	{
		//含有选项字节的话，填充选项字节
		//关于选项字节详见：http://blog.csdn.net/wdscq1234/article/details/52423272

		node->TCP_Head[20] = 0x02;		//kind == 2 (maximum segment size 最大报文长度)
		node->TCP_Head[21] = 0x04;		//len == 4
		node->TCP_Head[22] = MYTCPMSS>>8;		//value == 0x05b4(1460) 
		node->TCP_Head[23] = (uint8_t)MYTCPMSS;
		
		node->TCP_Head[24] = 0x01;		//NOP
		
		node->TCP_Head[25] = 0x03;		//kind == 3 (window scale 串口扩大因子)
		node->TCP_Head[26] = 0x03;		//len == 3
		node->TCP_Head[27] = 0x00;		//value == 0 () 
		
		node->TCP_Head[28] = 0x01;		//NOP
		node->TCP_Head[29] = 0x01;		//NOP
		node->TCP_Head[30] = 0x01;		//NOP
		node->TCP_Head[31] = 0x00;		//End of Options List	
	}

	//计算检验和
	uint32_t sum = MyIP_CheckSum((uint16_t *)(TCP_False),12);		//TCP伪首部12
	sum += MyIP_CheckSum((uint16_t *)(node->TCP_Head),(((node->TCP_Head[12])>>2)&0x3C) );				//TCP首部长
	sum += MyIP_CheckSum((uint16_t *)data,len);							//TCP首部20
	uint16_t tem = MyIP_CheckCode(sum);									//计算溢出位

    node->TCP_Head[16] = tem;
	node->TCP_Head[17] = tem>>8;					//检验和稍后补充

	return true;
}

/**
  * @brief	发送TCP数据包
  * @param	*node: 连接
  * @param	*data: 数据
  * @param	len: 数据长度

  * @return	uint8_t	
  * @remark 正确做法是还要判断对方窗口大小决定是否需要分片
  */
uint8_t Send_TCP_Bag(LINKSTRUCT *node,uint8_t TCP_Flag,const uint8_t *data,uint16_t len)
{
	if(node == NULL)
		return 1;	
	
	if(data == NULL && len != 0)
		return 2;
	
	//以太网帧头打包，类型 0 IP类型
	if(!EN_Head_Pack(node,node->Re_MAC,My_MAC,0x00))
		return 3;
	
	//TCP帧头打包，要先打包，算出帧头的长度
	if(!TCP_Head_Pack(node,TCP_Flag,2048,data,len))			//还有4个CRC校验
		return 4;
	
	uint8_t TCP_Head_Len = (((node->TCP_Head[12])>>2)&0x3C);				//TCP首部长
	//IP帧头打包,IP数据报类型1 TCP
	//IP_len : IP首部20+TCP首部+数据len
	if(!IP_Head_Pack(node,node->Re_IP,1,20+TCP_Head_Len+len))
		return 5;
	
	//发送TCP数据包
	TCP_Packet_Send(node->EN_Head,node->IP_Head,node->TCP_Head,data,len);
	return 0;
}

/**
  * @brief	TCP数据处理
  * @param	*data: 收到的所有数据，包括EN帧头14位、IP帧头20位
  * @param	len： 收到的所有数据长度，包括EN帧头14位、IP帧头20位

  * @return	void	
  * @remark		
  */
uint8_t TCP_Data_Process(const uint8_t *data,uint16_t len)
{
	uint8_t TCP_Flg;
	uint16_t DataStartIndex,DataLen,L_Port,R_Port;
	uint32_t TCP_Mark,TCP_CMark;
	if(!TCP_Data_Check(data,len,&DataStartIndex,&DataLen,&TCP_Flg,&L_Port,&R_Port,&TCP_Mark,&TCP_CMark))
	{
//		TCP_DEBUGOUT("tcp sum check error\r\n");
		return 1;
	}
#if 0	
	TCP_DEBUGOUT("\r\n");
//	printf("recev tcp bag,net:%d,RPort:%d,LPort:%d\r\n",LinkIndex,RPort,LPort);
	TCP_DEBUGOUT("en head: ");
	for(uint8_t i=0;i<14;i++)
		TCP_DEBUGOUT("%02X ",data[i]);
	TCP_DEBUGOUT("\r\n");
	
	TCP_DEBUGOUT("ip head: ");
	for(uint8_t i=0;i<20;i++)
		TCP_DEBUGOUT("%02X ",data[i+14]);
	TCP_DEBUGOUT("\r\n");
	
	TCP_DEBUGOUT("tcp head: ");
	for(uint8_t i=0;i<20;i++)
		TCP_DEBUGOUT("%02X ",data[i+34]);
	TCP_DEBUGOUT("\r\n");
	
	uint16_t datalen = (((uint16_t)(data[16]<<8))|data[17])-40;		//总长度,减去20IP头和8UDP头
	TCP_DEBUGOUT("tcp data(%d): ",datalen);
	for(uint8_t i=0;i<datalen;i++)
		TCP_DEBUGOUT("%02X ",data[i+54]);
	TCP_DEBUGOUT("\r\n");
	
	uint16_t tcpwindow = (((uint16_t)(data[48]<<8))|data[49]);		//TCP窗口大小
	TCP_DEBUGOUT("tcp windows: %d\r\n",tcpwindow);
	
#endif

#if 0
	TCP_DEBUGOUT("TCP Lport: %d\r\n",L_Port);
	TCP_DEBUGOUT("TCP Rport: %d\r\n",R_Port);
	TCP_DEBUGOUT("TCP Mark: %u\r\n",TCP_Mark);
	TCP_DEBUGOUT("TCP CMark: %u\r\n",TCP_CMark);
	TCP_DEBUGOUT("TCP flag: %02X\r\n",TCP_Flg);
//	TCP_DEBUGOUT("data len: %d\r\n",DataLen);
//	TCP_DEBUGOUT("data index: %d\r\n",DataStartIndex);
#endif

	uint16_t LinkIndex;

	//检查是哪个连接的数据包
	if(!MyIP_CheckSocket((TCP_CLIENT|TCP_SERVER),L_Port,&LinkIndex))
	{
//		TCP_DEBUGOUT("local port not found\r\n");
		return 2;
	}

	//跟本机握手
	if(TCP_Flg == TCPFLG_SYN)
	{
		if(MyNet[LinkIndex].Net_Type == TCP_SERVER)
		{
			//当前连接处于监听状态
			if(MyNet[LinkIndex].Cur_Stat == TCP_LISTEN)
			{
				MyNet[LinkIndex].TCP_Mark = 0x1200;		//序号
				MyNet[LinkIndex].TCP_CMark = TCP_Mark+1;
				MyNet[LinkIndex].Re_Port = R_Port;
//				MyNetConfig_ReMAC(&MyNet[LinkIndex],data+6);			//复制远程MAC
				memcpy(MyNet[LinkIndex].Re_MAC,data+6,6);				//复制远程MAC
//				MyNetConfig_ReIP(&MyNet[LinkIndex],data+26);			//复制远程IP
				memcpy(MyNet[LinkIndex].Re_IP,data+26,4);
				//记录到ARP缓存中
				ARPCache_Write(data+26,data+6);
				
				//发送SYN|ASK
				Send_TCP_Bag(&MyNet[LinkIndex],(TCPFLG_ACK|TCPFLG_SYN),NULL,0);
				
				//收到SYN,并发送了SYN|ASK后，将状态改为SYNRECEIVED
				MyNet[LinkIndex].Cur_Stat = TCP_SYNRECEIVED;
			}
		}
		return 0;
	}
	//收到ACK
	if(TCP_Flg == TCPFLG_ACK)
	{
		if(MyNet[LinkIndex].Net_Type == TCP_SERVER)
		{
			//当前连接处于等待客户端发送TCPFLG_ACK
			if(MyNet[LinkIndex].Cur_Stat == TCP_SYNRECEIVED)
			{
				MyNet[LinkIndex].TCP_Mark = TCP_CMark;		//序号
				MyNet[LinkIndex].TCP_CMark = TCP_Mark;
				//收到ACK，将状态改为ESTABLISHED,不发送
				MyNet[LinkIndex].Cur_Stat = TCP_ESTABLISHED;
				
				//记录客户端IP和MAC到ARP缓存表中
				
				//建立了连接，进入数据传输状态，允许数据发送
				MyNet[LinkIndex].Net_Flg.reg.Wait_Ack = 0;
			}
			else if(MyNet[LinkIndex].Cur_Stat == TCP_ESTABLISHED)
			{
				//数据传送状态下，发出数据后收到对方的ACK
				MyNet[LinkIndex].TCP_Mark = TCP_CMark;		//序号
//				MyNet[LinkIndex].TCP_CMark = TCP_Mark;
				MyNet[LinkIndex].Net_Flg.reg.Data_Recv = 1;
				
				//如果是收到keepalive的话还要回应keepaliveack
				if(MyNet[LinkIndex].TCP_CMark == TCP_Mark+1)
				{
					MyNet[LinkIndex].TCP_CMark = TCP_Mark+1;
					//回复keepaliveACK包
					Send_TCP_Bag(&MyNet[LinkIndex],TCPFLG_ACK,NULL,0);
				}
				else
				{
					MyNet[LinkIndex].TCP_CMark = TCP_Mark;
				}
				//数据传送状态，收到对方应答，允许数据发送
				MyNet[LinkIndex].Net_Flg.reg.Wait_Ack = 0;
			}
//			else if(MyNet[LinkIndex].Cur_Stat == TCP_CLOSEWAIT)
//			{
//			}
			else if(MyNet[LinkIndex].Cur_Stat == TCP_LASTASK)
			{
				MyNet[LinkIndex].Cur_Stat = TCP_LISTEN;
			}
		}
		else if(MyNet[LinkIndex].Net_Type == TCP_CLIENT)
		{
			if(MyNet[LinkIndex].Cur_Stat==TCP_FINWAIT1)
			{
				MyNet[LinkIndex].Cur_Stat = TCP_FINWAIT2;
			}
			else if(MyNet[LinkIndex].Cur_Stat==TCP_ESTABLISHED)
			{
				//数据传送状态下，发出数据后收到对方的ACK
				MyNet[LinkIndex].TCP_Mark = TCP_CMark;		//序号
//				MyNet[LinkIndex].TCP_CMark = TCP_Mark;
				MyNet[LinkIndex].Net_Flg.reg.Data_Recv = 1;
				
				//如果是收到keepalive的话还要回应keepaliveack
				if(MyNet[LinkIndex].TCP_CMark == TCP_Mark+1)
				{
					MyNet[LinkIndex].TCP_CMark = TCP_Mark+1;
					//回复keepaliveACK包
					Send_TCP_Bag(&MyNet[LinkIndex],TCPFLG_ACK,NULL,0);
				}
				else
				{
					MyNet[LinkIndex].TCP_CMark = TCP_Mark;
				}
				
				//数据传输状态，收到对方的ACK，允许数据发送
				MyNet[LinkIndex].Net_Flg.reg.Wait_Ack = 0;
			}
			else if(MyNet[LinkIndex].Cur_Stat==TCP_CLOSING)
			{
				//状态改为TIMEWAIT
				MyNet[LinkIndex].Cur_Stat = TCP_TIMEWAIT;
				
				//2MSL后改为CLOSED（在状态机处理）
			}
			else if(MyNet[LinkIndex].Cur_Stat==TCP_SYNSENT)
			{
				//客户端发送SYN后收到了服务器的ACK
				//此时需要改变本地端口
//				MyNet[LinkIndex].Lc_Port = MyIP_GetLocalPort();
			}
		}
		return 0;
	}
	//收到FIN
	else if( (TCP_Flg&TCPFLG_FIN) == TCPFLG_FIN )
	{
//		TCP_DEBUGOUT("TCP flag FIN\r\n");
		//判断当前状态
		if(MyNet[LinkIndex].Net_Type == TCP_SERVER)
		{
			if(MyNet[LinkIndex].Cur_Stat == TCP_ESTABLISHED)
			{
				MyNet[LinkIndex].TCP_Mark = TCP_CMark;		//序号
				MyNet[LinkIndex].TCP_CMark = TCP_Mark+1;
				//数据传送过程中收到FIN，为对方断开连接
				//先发ASK
				Send_TCP_Bag(&MyNet[LinkIndex],TCPFLG_ACK,NULL,0);
				MyNet[LinkIndex].Cur_Stat = TCP_CLOSEWAIT;
				
				//进程关闭后再发FIN ASK
				//此处没有进程可关闭，直接接着发FIN ASK
				Send_TCP_Bag(&MyNet[LinkIndex],(TCPFLG_FIN|TCPFLG_ACK),NULL,0);
				MyNet[LinkIndex].Cur_Stat = TCP_LASTASK;
			}
			else if(MyNet[LinkIndex].Cur_Stat == TCP_CLOSEWAIT)
			{
				//服务器主动断开连接的过程中
				//收到客户端发来的FIN|ACK后回应ACK
				MyNet[LinkIndex].TCP_Mark = TCP_CMark;		//序号
				MyNet[LinkIndex].TCP_CMark = TCP_Mark+1;
				Send_TCP_Bag(&MyNet[LinkIndex],TCPFLG_ACK,NULL,0);
				
				//服务器状态转入CLOSED
				//需要重新打开服务器进入LISTEN状态才能被客户端连接
				MyNet[LinkIndex].Cur_Stat = CLOSE;
			}
		}
		else if(MyNet[LinkIndex].Net_Type == TCP_CLIENT)
		{
			if(MyNet[LinkIndex].Cur_Stat==TCP_FINWAIT1)
			{
				//只收到FIN
				if(TCP_Flg==TCPFLG_FIN)
				{
					//状态改为CLOSING
					MyNet[LinkIndex].Cur_Stat = TCP_CLOSING;
				}
				//有FIN 和 ACK
				else if( (TCP_Flg&TCPFLG_ACK) == TCPFLG_ACK )
				{	
					//状态改为TIMEWAIT
					MyNet[LinkIndex].Cur_Stat = TCP_TIMEWAIT;
					
					//2MSL后改为CLOSED（在状态机处理）
				}
				//发ASK
				Send_TCP_Bag(&MyNet[LinkIndex],TCPFLG_ACK,NULL,0);
			}
			else if(MyNet[LinkIndex].Cur_Stat==TCP_FINWAIT2)
			{
				MyNet[LinkIndex].TCP_Mark = TCP_CMark;		//序号
				MyNet[LinkIndex].TCP_CMark = TCP_Mark+1;
				//发ASK
				Send_TCP_Bag(&MyNet[LinkIndex],TCPFLG_ACK,NULL,0);
				
				//状态改为TIMEWAIT
				MyNet[LinkIndex].Cur_Stat = TCP_TIMEWAIT;
				
				//2MSL后改为CLOSED（在状态机处理），RFC 793中规定是2分钟，此处按30秒来
			}
			else if(MyNet[LinkIndex].Cur_Stat==TCP_TIMEWAIT)
			{
				//在TIMEWAIT状态下又收到对方发来的FIN，说明发出的ACK对方没有收到
				//重新发送ACK
				MyNet[LinkIndex].TCP_Mark = TCP_CMark;		//序号
				MyNet[LinkIndex].TCP_CMark = TCP_Mark+1;
				//发ASK
				Send_TCP_Bag(&MyNet[LinkIndex],TCPFLG_ACK,NULL,0);
			}
			//数据传送过程中服务器发送了断开连接的请求
			else if(MyNet[LinkIndex].Cur_Stat==TCP_ESTABLISHED)
			{
				MyNet[LinkIndex].TCP_Mark = TCP_CMark;		//序号
				MyNet[LinkIndex].TCP_CMark = TCP_Mark+1;
				
				//状态改为FINWAIT1
				MyNet[LinkIndex].Cur_Stat = TCP_FINWAIT1;
				//发ASK
				Send_TCP_Bag(&MyNet[LinkIndex],TCPFLG_ACK,NULL,0);
				
				//状态改为CLOSING
				MyNet[LinkIndex].Cur_Stat = TCP_CLOSING;
				//发FIN|ASK
				Send_TCP_Bag(&MyNet[LinkIndex],(TCPFLG_FIN|TCPFLG_ACK),NULL,0);
			}
		}
		return 0;
	}
	//收到RST
	else if( (TCP_Flg&TCPFLG_RST) == TCPFLG_RST )
	{
//		TCP_DEBUGOUT("TCP flag RST\r\n");
		MyNet[LinkIndex].TCP_Mark = TCP_CMark;		//序号
		MyNet[LinkIndex].TCP_CMark = 0;
		
		if(MyNet[LinkIndex].Net_Type == TCP_SERVER)
		{
			MyNet[LinkIndex].Cur_Stat = TCP_LISTEN;
		}
		else if(MyNet[LinkIndex].Net_Type == TCP_CLIENT)
		{
//			MyNet[LinkIndex].Cur_Stat = TCP_CLOSED;
			MyNet[LinkIndex].Cur_Stat = CLOSE;
		}
	}
	//收到SYN|ACK
	else if(TCP_Flg == (TCPFLG_SYN|TCPFLG_ACK) )
	{
//		TCP_DEBUGOUT("TCP flag SYN|ACK\r\n");
		//客户端收到SYN|ASK
		if(MyNet[LinkIndex].Net_Type == TCP_CLIENT)
		{
			if(MyNet[LinkIndex].Cur_Stat == TCP_SYNSENT)
			{
				MyNet[LinkIndex].TCP_Mark = TCP_CMark;		//序号
				MyNet[LinkIndex].TCP_CMark = TCP_Mark+1;
				MyNet[LinkIndex].Cur_Stat = TCP_ESTABLISHED;
				//建立了连接，进入数据传输状态，允许数据发送
				MyNet[LinkIndex].Net_Flg.reg.Wait_Ack = 0;
				
				//回复包
				Send_TCP_Bag(&MyNet[LinkIndex],TCPFLG_ACK,NULL,0);
			}
		}
	}
	else if( (TCP_Flg&TCPFLG_PSH) || (TCP_Flg&TCPFLG_ACK) )
	{
		//收到数据包，或者收到发出数据包的应答
		//当前正在数据传送状态
		if(MyNet[LinkIndex].Cur_Stat == TCP_ESTABLISHED)
		{
			MyNet[LinkIndex].Net_Flg.reg.Data_Recv = 1;
			//将数据保存到队列中等待做处理
			//数据起始地址 data+DataStartIndex;
			//数据长度 DataLen
			//确认序号等于对方的序号加上我实际接收的长度
//#if 0
//			if(TCP_Data_Recev(LinkIndex,data+DataStartIndex,DataLen))
//			{
//				MyNet[LinkIndex].TCP_Mark = TCP_CMark;		//序号
//				MyNet[LinkIndex].TCP_CMark = TCP_Mark+DataLen;
//			}
//			else
//			{
//				MyNet[LinkIndex].TCP_Mark = TCP_CMark;		//序号
//				MyNet[LinkIndex].TCP_CMark = TCP_Mark;
//			}
//#else
//			MyNet[LinkIndex].TCP_Mark = TCP_CMark;		//序号
//			MyNet[LinkIndex].TCP_CMark = TCP_Mark+TCP_Data_Recev(LinkIndex,data+DataStartIndex,DataLen);
//#endif
	
			MyNet[LinkIndex].TCP_Mark = TCP_CMark;		//序号
			//如果对方没收到ACK，则又会重新传一遍数据，需要根据MARK判断是不是重传的数据
			if(MyNet[LinkIndex].TCP_CMark != (TCP_Mark+DataLen) )
			{
				MyNet[LinkIndex].TCP_CMark = TCP_Mark+TCP_Data_Recev(LinkIndex,data+DataStartIndex,DataLen);
			}
			//回复包
			Send_TCP_Bag(&MyNet[LinkIndex],TCPFLG_ACK,NULL,0);
		}
	}
	return 0;
}

