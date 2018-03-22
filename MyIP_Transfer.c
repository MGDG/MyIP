/**
  ******************************************************************************
  * @file    MyIP_Transfer.c
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   网卡数据传输
  ******************************************************************************
 **/
#include "MyIP_Transfer.h"
#include "MyIP_TCPIP.h"
#include "enc28j60.h"

uint16_t MyIP_PacketReceive(uint8_t* packet,uint16_t maxlen)	 //接收数据包函数，最大长度 数据
{
	extern uint16_t NextPacketPtr;
	static uint16_t NextPackLen=0,ReadedPackLen=0;		//下次是否继续接收
	static uint16_t CurrentPacketPtr;	  	//保存当前包的位置
	uint16_t rxstat;
    uint16_t len;
	
	if(packet == NULL)
		return 0;

	if(NextPackLen==0)		//如果接收的包在缓存范围内
	{
		// 检查缓冲是否一个包已经收到
		if( !(enc28j60Read(EIR) & EIR_PKTIF) )
	    {
	        // 通过查看EPKTCNT寄存器再次检查是否收到包
			if (enc28j60Read(EPKTCNT) == 0)
	            return 0;
	    }
	    
		//设置接收到的数据包读指针开始
		enc28j60Write(ERDPTL, (NextPacketPtr));
	    enc28j60Write(ERDPTH, (NextPacketPtr)>>8);
		CurrentPacketPtr=NextPacketPtr;

	    // 下一个封包读指针
		NextPacketPtr  = enc28j60ReadOp(ENC28J60_READ_BUF_MEM, 0);
	    NextPacketPtr |= enc28j60ReadOp(ENC28J60_READ_BUF_MEM, 0)<<8;
	
	    // 读取包的长度
		len  = enc28j60ReadOp(ENC28J60_READ_BUF_MEM, 0);
	    len |= enc28j60ReadOp(ENC28J60_READ_BUF_MEM, 0)<<8;
		len-=4;// 移除CRC字段的长度来减少MAC所报告长度
	
		// 读取接收数据包的状态
		rxstat  = enc28j60ReadOp(ENC28J60_READ_BUF_MEM, 0);
		rxstat |= enc28j60ReadOp(ENC28J60_READ_BUF_MEM, 0)<<8;
	    //if ((rxstat & 0x80)==0)	return 0; 	    // invalid
	
	    // 计算实际数据长度
		if(len>maxlen)
		{
			NextPackLen=len-maxlen;	 		//剩余字节
			len=maxlen;
			// copy the packet from the receive buffer
		    enc28j60ReadBuffer(len, packet);
			packet[16]=(len-42+28)>>8; 		//修改IP包已接收包长度,这里只有接收UDP包时才会出现超出长度
			packet[17]=len-42+28;			//,不用担心TCP,因为TCP有窗大小限制,不会超出长度
		}
		else
		{
			NextPackLen=0;
			// copy the packet from the receive buffer
		    enc28j60ReadBuffer(len, packet);
		}

		ReadedPackLen=len;		//已读长度

	}
	else 		//如果是上次没有收完的包
	{
		if(NextPackLen>maxlen-42)		//减掉UDP包头42字节，TCP无此问题
		{
			NextPackLen=NextPackLen-(maxlen-42);
			len=maxlen-42;
		}
		else
		{
			len=NextPackLen;
			NextPackLen=0;
		}

		//设置接收到的数据包读指针开始
		enc28j60Write(ERDPTL, (CurrentPacketPtr+6));	   	//跳过前面6字节的长度信息
	    enc28j60Write(ERDPTH, (CurrentPacketPtr+6)>>8);
		enc28j60ReadBuffer(42, packet);		//读出包头，目前支持UDP包头为42字节，TCP不会出现这种情况
		packet[16]=(len+28)>>8; 		//修改IP包已接收包长度,这里只有接收UDP包时才会出现超出长度
		packet[17]=len+28;				//,不用担心TCP,因为TCP有窗大小限制,不会超出长度

		enc28j60Write(ERDPTL, (CurrentPacketPtr+6+ReadedPackLen));	   	//跳到上次读完的位置处开始读
	    enc28j60Write(ERDPTH, (CurrentPacketPtr+6+ReadedPackLen)>>8); 	
		enc28j60ReadBuffer(len, packet+42);		//读出剩下的内容
		ReadedPackLen+=len;

		len+=42;
	}
	
	if(NextPackLen==0)		 		//清除本包所占模块的缓存空间
	{
	    // ERXRDPT读缓冲器指针
		// ENC28J60将一直写到该指针之前的一单元为止
	    enc28j60Write(ERXRDPTL, (NextPacketPtr));
	    enc28j60Write(ERXRDPTH, (NextPacketPtr)>>8);
	    // Errata workaround #13. Make sure ERXRDPT is odd

	    // 数据包个数递减位EPKTCNT减1
		enc28j60WriteOp(ENC28J60_BIT_FIELD_SET, ECON2, ECON2_PKTDEC);  
	}

    return len;
}

void ARP_Packet_Send(const uint8_t *EN_Head,const uint8_t *ARP_Head)
{
	if(EN_Head==NULL || ARP_Head==NULL)
		return;
	
	// 设置写指针开始的传输缓冲区域
	enc28j60Write(EWRPTL, (uint8_t)TXSTART_INIT);
    enc28j60Write(EWRPTH, TXSTART_INIT>>8);

    // 设置TXND指向对应于给定的数据包大小
	enc28j60Write(ETXNDL, (uint8_t)(TXSTART_INIT+42));//14为以太网头+28 ARP数据包长度
    enc28j60Write(ETXNDH, (TXSTART_INIT+42)>>8);

    // 写每个包的控制字
	enc28j60WriteOp(ENC28J60_WRITE_BUF_MEM, 0, 0x00);

    // TODO, fix this up
	    // 以太网头 到传输缓冲
		enc28j60WriteBuffer(14, EN_Head);
		// ARP数据包 到传输缓冲
		enc28j60WriteBuffer(28, ARP_Head);
	    

	// 将以太网控制寄存器ECON1所有位 置1，以发送缓冲区数据
	enc28j60WriteOp(ENC28J60_BIT_FIELD_SET, ECON1, ECON1_TXRTS);
}

void UDP_Packet_Send(const uint8_t *EN_Head,const uint8_t *IP_Head,const uint8_t *UDP_Head,const uint8_t *DATA,uint16_t len)
{
	if(EN_Head==NULL || IP_Head==NULL || UDP_Head==NULL)
		return;
	
	if(DATA == NULL && len != 0)
		return;
	
	// 设置写指针开始的传输缓冲区域
	enc28j60Write(EWRPTL, (uint8_t)TXSTART_INIT);
    enc28j60Write(EWRPTH, TXSTART_INIT>>8);

    // 设置TXND指向对应于给定的数据包大小
	enc28j60Write(ETXNDL, (TXSTART_INIT+42+len));//14为以太网头+20IP头+8UDP头+len数据包长度
    enc28j60Write(ETXNDH, (TXSTART_INIT+42+len)>>8);

    // 写每个包的控制字
	enc28j60WriteOp(ENC28J60_WRITE_BUF_MEM, 0, 0x00);

    // TODO, fix this up

    
        // 以太网头 到传输缓冲
		enc28j60WriteBuffer(14, EN_Head);
		// IP头 到传输缓冲
		enc28j60WriteBuffer(20, IP_Head);
		// UDP头 到传输缓冲
		enc28j60WriteBuffer(8, UDP_Head);
		// UDP数据 到传输缓冲
		if(len != 0)
			enc28j60WriteBuffer(len, DATA);
    

	// 将以太网控制寄存器ECON1所有位 置1，以发送缓冲区数据
	enc28j60WriteOp(ENC28J60_BIT_FIELD_SET, ECON1, ECON1_TXRTS);
}

void TCP_Packet_Send(const uint8_t *EN_Head,const uint8_t *IP_Head,const uint8_t *TCP_Head,const uint8_t *DATA,uint16_t len)
{
	if(EN_Head==NULL || IP_Head==NULL || TCP_Head==NULL)
		return;
	
	if(DATA == NULL && len != 0)
		return;
	
	uint8_t tcp_head_len = (((TCP_Head[12])>>2)&0x3C);
	
	// 设置写指针开始的传输缓冲区域
	enc28j60Write(EWRPTL, (uint8_t)TXSTART_INIT);
    enc28j60Write(EWRPTH, TXSTART_INIT>>8);

    // 设置TXND指向对应于给定的数据包大小
	uint16_t Totail_len = (TXSTART_INIT+14+20+tcp_head_len+len);		//TXSTART_INIT+54+len
	enc28j60Write(ETXNDL, (uint8_t)Totail_len);//14为以太网头+20IP头+20TCP头+len数据包长度
    enc28j60Write(ETXNDH, Totail_len>>8);

    // 写每个包的控制字
	enc28j60WriteOp(ENC28J60_WRITE_BUF_MEM, 0, 0x00);

    // TODO, fix this up
        // 以太网头 到传输缓冲
		enc28j60WriteBuffer(14, EN_Head);
		// IP头 到传输缓冲
		enc28j60WriteBuffer(20, IP_Head);
		// TCP头 到传输缓冲
		enc28j60WriteBuffer(tcp_head_len, TCP_Head);
		// UDP数据 到传输缓冲
		if(len != 0)
			enc28j60WriteBuffer(len,DATA);

    

	// 将以太网控制寄存器ECON1所有位 置1，以发送缓冲区数据
	enc28j60WriteOp(ENC28J60_BIT_FIELD_SET, ECON1, ECON1_TXRTS);
}

void ICMP_Ping_Packet_Send(const uint8_t *EN_Head,const uint8_t *IP_Head,const uint8_t *ICMP_Head,uint16_t ICMP_len)
{
	if(EN_Head==NULL || IP_Head==NULL || ICMP_Head==NULL)
		return;
	
	// 设置写指针开始的传输缓冲区域
	enc28j60Write(EWRPTL, (uint8_t)TXSTART_INIT);
    enc28j60Write(EWRPTH, TXSTART_INIT>>8);

    // 设置TXND指向对应于给定的数据包大小
	enc28j60Write(ETXNDL, (uint8_t)(TXSTART_INIT+34+ICMP_len));//14为以太网头+20IP头+40ICMP_Ping数据包长度
    enc28j60Write(ETXNDH, (TXSTART_INIT+34+ICMP_len)>>8);

    // 写每个包的控制字
	enc28j60WriteOp(ENC28J60_WRITE_BUF_MEM, 0, 0x00);

    // TODO, fix this up
        // 以太网头 到传输缓冲
		enc28j60WriteBuffer(14, EN_Head);
		// IP头 到传输缓冲
		enc28j60WriteBuffer(20, IP_Head);
		// ICMP 到传输缓冲
		enc28j60WriteBuffer(ICMP_len, ICMP_Head);


	// 将以太网控制寄存器ECON1所有位 置1，以发送缓冲区数据
	enc28j60WriteOp(ENC28J60_BIT_FIELD_SET, ECON1, ECON1_TXRTS);
}

/**
  * @brief	UDP数据接收
  * @param	sockfd: 已经创建的某个连接
  * @param	*data: 收到的有效数据
  * @param	len： 有效数据的长度

  * @return	void	
  * @remark	将接收到的数据存入队列
  */
void UDP_Data_Recev(uint16_t sockfd,const uint8_t *data,uint16_t len)
{
	printf("udp(%d) recev: ",sockfd);
	for(size_t i=0;i<len;i++)
		printf("%c",data[i]);
	printf("\r\n");
}

/**
  * @brief	TCP数据接收
  * @param	sockfd: 已经创建的某个连接
  * @param	*data: 收到的有效数据
  * @param	len： 有效数据的长度

  * @return	uint16_t	
  * @remark	将接收到的数据存入队列，返回实际保存成功的数据大小
  */
uint16_t TCP_Data_Recev(uint16_t sockfd,const uint8_t *data,uint16_t len)
{
	printf("tcp(%d) recev: ",sockfd);
	for(uint16_t i=0;i<len;i++)
		printf("%c",data[i]);
	printf("\r\n");
	return len;
}
