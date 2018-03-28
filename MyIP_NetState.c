/**
  ******************************************************************************
  * @file    MyIP_NetState.c
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-03-07
  * @brief   状态机
  ******************************************************************************
 **/
#include "MyIP_NetState.h"
#include "MyIP_TCP.h"
#include "MyIP_DHCP.h"
#include "MyIP_ARP.h"

#define NETSTATE_DEBUGOUT(...)	TCPDEBUGOUT(__VA_ARGS__)

#if USE_DHCP==1
extern bool DHCP_FinishFlg;
#endif	
/**
  * @brief	网络状态机处理
  * @param	TimeInterVal: 不调用间隔，单位ms

  * @return	void	
  * @remark		
  */

void MyIP_NetState(void)
{
#if USE_DHCP==1
	if(DHCP_FinishFlg == false)
	{
		switch(MyNet[0].Cur_Stat)
		{
			case CLOSE:
			{
				if(MyNet[0].Cur_Stat != MyNet[0].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("STATE CLOSE ENTRY\r\n");		
					MyNet[0].Pre_Stat = MyNet[0].Cur_Stat;	
//					MyNet[0].Time_Count = MyIP_GetNowTime();		//获取当前时间
//					MyNet[0].Re_Sent = 0;							//重发次数清0
				}
			}
			break;

			case DHCP_DISCOVER:
			{
				if(MyNet[0].Cur_Stat != MyNet[0].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("STATE DHCP DISCOVER ENTRY\r\n");		
					MyNet[0].Pre_Stat = MyNet[0].Cur_Stat;	
					MyNet[0].Time_Count = MyIP_GetNowTime();			//获取当前时间
					MyNet[0].Re_Sent = 0;									//重发次数清0
					
					//发送DISCOVER
					DHCP_Send_Discover();
					
					DHCP_FinishFlg = false;
				}
				
				//等待服务器返回OFFER并进入REQUEST状态
				//没有回复则间隔1,2,4,8,16秒重发,后转失败,此处为方便实现，改为间隔2,4,6,8,10秒重发 (2*(MyNet[i].Re_Sent+1))
				//改成间隔3s好了
				else if(MyIP_GetElapsedTime(MyNet[0].Time_Count) >= 3 )
				{
					MyNet[0].Time_Count = MyIP_GetNowTime();
					
					if(MyNet[0].Re_Sent < 5)
					{
						MyNet[0].Re_Sent++;
						//超时后重发DISCOVER
						DHCP_Send_Discover();
					}
					else
					{
						//重发超过6次后服务器无应答，回到CLOSED状态
//						MyNet[0].Cur_Stat = CLOSE;
//						NETSTATE_DEBUGOUT("DHCP discover no answer\r\n");	
						
						//通知应用层IP获取失败
						MyNet[0].Re_Sent = 0;
					}
				}
			}
			break;

			case DHCP_OFFER:
			{
				if(MyNet[0].Cur_Stat != MyNet[0].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("STATE DHCP OFFER ENTRY\r\n");		
					MyNet[0].Pre_Stat = MyNet[0].Cur_Stat;	
//					MyNet[0].Time_Count = MyIP_GetNowTime();		//获取当前时间
//					MyNet[0].Re_Sent = 0;							//重发次数清0
				}
				
				//收到了DHCP服务器发来的OFFER，进入REQUEST状态
				MyNet[0].Cur_Stat = DHCP_REQUEST;
			}
			break;

			case DHCP_REQUEST:
			{
				if(MyNet[0].Cur_Stat != MyNet[0].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("STATE DHCP REQUEST ENTRY\r\n");		
					MyNet[0].Pre_Stat = MyNet[0].Cur_Stat;	
					MyNet[0].Time_Count = MyIP_GetNowTime();		//获取当前时间
					MyNet[0].Re_Sent = 0;								//重发次数清0
					
					//广播发送REQUEST
					DHCP_Send_Request(0);
				}
				//等待服务器返回ACK
				else if(MyIP_GetElapsedTime(MyNet[0].Time_Count) >= 2)
				{
					MyNet[0].Time_Count = MyIP_GetNowTime();
					
					if(MyNet[0].Re_Sent < 5)
					{
						MyNet[0].Re_Sent++;
						//超时后重发，广播发送REQUEST
						DHCP_Send_Request(0);
					}
					else
					{
						//重发超过6次后服务器无应答，进入DISCOVER状态重新发送广播请求
						MyNet[0].Cur_Stat = DHCP_DISCOVER;
						NETSTATE_DEBUGOUT("DHCP request no answer\r\n");	
					}
				}
			}
			break;

			case DHCP_ACK:
			{
				if(MyNet[0].Cur_Stat != MyNet[0].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("STATE DHCP ASK ENTRY\r\n");		
					MyNet[0].Pre_Stat = MyNet[0].Cur_Stat;	
//					MyNet[0].Time_Count = MyIP_GetNowTime();		//获取当前时间
//					MyNet[0].Re_Sent = 0;							//重发次数清0
				}
				
				//ip获取完毕，进入CLOSE状态
				MyNet[0].Cur_Stat = CLOSE;
				
				DHCP_FinishFlg = true;
			}
			break;

			case DHCP_NACK:
			{
				if(MyNet[0].Cur_Stat != MyNet[0].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("STATE DHCP NASK ENTRY\r\n");		
					MyNet[0].Pre_Stat = MyNet[0].Cur_Stat;	
//					MyNet[0].Time_Count = MyIP_GetNowTime();		//获取当前时间
//					MyNet[0].Re_Sent = 0;							//重发次数清0
				}
				
				//重新开始发送DISCOVER
				MyNet[0].Cur_Stat = DHCP_DISCOVER;
			}
			break;
		}
		
		return;
	}
#endif	
	uint16_t NetNum = sizeof(MyNet)/sizeof(MyNet[0]);
	for(uint16_t i=1;i<NetNum;i++)
	{
		switch(MyNet[i].Cur_Stat)
		{
//CLOSE
			case CLOSE:
			{
				if(MyNet[i].Cur_Stat != MyNet[i].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("Socket(%d) STATE CLOSE ENTRY\r\n",i);		
					MyNet[i].Pre_Stat = MyNet[i].Cur_Stat;	
				}
			}
			break;
//ARP
			case ARP_REQUEST:
			{
				if(MyNet[i].Cur_Stat != MyNet[i].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("Socket(%d) STATE ARP REQUEST ENTRY\r\n",i);		
					MyNet[i].Pre_Stat = MyNet[i].Cur_Stat;
					MyNet[i].Time_Count = MyIP_GetNowTime();			//获取当前时间
					MyNet[i].Re_Sent = 0;									//重发次数清0	
					MyNet[i].Net_Flg.reg.ARPOK = 0;
					ARP_Request(MyNet[i].Re_IP);					
				}
				if(MyNet[i].Net_Flg.reg.ARPOK != 1)
				{
					if(MyIP_GetElapsedTime(MyNet[i].Time_Count) >= 2)
					{
						MyNet[i].Time_Count = MyIP_GetNowTime();
						
						MyNet[i].Re_Sent++;
						//超过两秒依然没有获得ARP应答
						//重新发送ARP请求
						if(MyNet[i].Re_Sent < 3)
						{
							ARP_Request(MyNet[i].Re_IP);	
						}
						else
						{
							NETSTATE_DEBUGOUT("Socket(%d) ARP request timeout\r\n",i);	
							MyNet[i].Cur_Stat = CLOSE;
						}
					}
				}
				else
				{
					MyNet[i].Cur_Stat=ARP_ANSWER;
				}
			}
			break;

			case ARP_ANSWER:
			{
				if(MyNet[i].Cur_Stat != MyNet[i].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("Socket(%d) STATE ARP ANSWER ENTRY\r\n",i);		
					MyNet[i].Pre_Stat = MyNet[i].Cur_Stat;
//					MyNet[i].Time_Count = MyIP_GetNowTime();			//获取当前时间
//					MyNet[i].Re_Sent = 0;									//重发次数清0						
				}
				
				//获得ARP应答，如果是客服端的话，要将状态切换到对应的状态
				if(MyNet[i].Net_Type==UDP_CLIENT || MyNet[i].Net_Type==UDP_SERVER)
				{
					MyNet[i].Cur_Stat=UDP_CONNECT;
				}
				else if(MyNet[i].Net_Type==TCP_CLIENT)	//和TCP服务器主动握手
				{
					//开始握手
					MyNet[i].Cur_Stat=TCP_SYNSENT;
				}
				else if(MyNet[i].Net_Type==TCP_SERVER)
				{
					//开始监听
					MyNet[i].Cur_Stat=TCP_LISTEN;
				}
			}
			break;
//UDP
			case UDP_CONNECT:
			{
				if(MyNet[i].Cur_Stat != MyNet[i].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("Socket(%d) STATE UDP CONNECT ENTRY\r\n",i);		
					MyNet[i].Pre_Stat = MyNet[i].Cur_Stat;	
					
					//先从ARP缓存表中读取MAC，读取成功则进入TRABSFER状态，读取失败则先进入ARP
					if(ARPCache_Read(MyNet[i].Re_IP,MyNet[i].Re_MAC))
					{
						MyNet[i].Cur_Stat = UDP_TRANSFER;
					}
					else
					{
						//进入REQUEST状态，获取对法MAC地址
						MyNet[i].Cur_Stat = ARP_REQUEST;
					}
				}
			}
			break;
			
			case UDP_TRANSFER:
			{
				if(MyNet[i].Cur_Stat != MyNet[i].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("Socket(%d) STATE UDP TRANSFER ENTRY\r\n",i);		
					MyNet[i].Pre_Stat = MyNet[i].Cur_Stat;	
				}
			}
			break;
//TCP
			case TCP_LISTEN:
			{
				if(MyNet[i].Cur_Stat != MyNet[i].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("Socket(%d) STATE TCP LISTEN ENTRY\r\n",i);		
					MyNet[i].Pre_Stat = MyNet[i].Cur_Stat;
//					MyNet[i].Time_Count = MyIP_GetNowTime();		//获取当前时间
//					MyNet[i].Re_Sent = 0;							//重发次数清0				
				}
			}
			break;

			case TCP_SYNRECEIVED:
			{
				if(MyNet[i].Cur_Stat != MyNet[i].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("Socket(%d) STATE TCP SYNRECEIVED ENTRY\r\n",i);		
					MyNet[i].Pre_Stat = MyNet[i].Cur_Stat;	
					MyNet[i].Time_Count = MyIP_GetNowTime();		//获取当前时间
					MyNet[i].Re_Sent = 0;								//重发次数清0
				}
				if(MyIP_GetElapsedTime(MyNet[i].Time_Count) >= 2)	//计时超过两秒
				{
					MyNet[i].Time_Count = MyIP_GetNowTime();
					
					//该状态下，服务器发送了SYN|ACK
					//并等待收到ASK并进入ESTABLISHED
					if(MyNet[i].Net_Type == TCP_SERVER)
					{
						if(MyNet[i].Re_Sent < 3)
						{
							//超时后重发SYN|ASK
							MyNet[i].Re_Sent++;
							Send_TCP_Bag(&MyNet[i],(TCPFLG_ACK|TCPFLG_SYN),NULL,0);
						}
						else
						{
							//重发超过3次后回到LISTEN状态
							MyNet[i].Cur_Stat = TCP_LISTEN;
						}
					}
				}
			}
			break;

			case TCP_SYNSENT:
			{
				if(MyNet[i].Cur_Stat != MyNet[i].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("Socket(%d) STATE TCP SYNSENT ENTRY\r\n",i);		
					MyNet[i].Pre_Stat = MyNet[i].Cur_Stat;	
					MyNet[i].Time_Count = MyIP_GetNowTime();		//获取当前时间
					MyNet[i].Re_Sent = 0;								//重发次数清0
					
					//先从ARP缓存表中读取MAC，读取成功则发送SYN，读取失败则先进入ARP
					if(ARPCache_Read(MyNet[i].Re_IP,MyNet[i].Re_MAC))
					{
						//发送握手包
						Send_TCP_Bag(&MyNet[i],TCPFLG_SYN,NULL,0);
					}
					else
					{
						//进入REQUEST状态，获取对方MAC地址
						MyNet[i].Cur_Stat = ARP_REQUEST;
					}
				}
				//客户端发出SYN后需等待服务器返回SYN|ACK
				if(MyIP_GetElapsedTime(MyNet[i].Time_Count) >= 2)
				{
					MyNet[i].Time_Count = MyIP_GetNowTime();
					
					//等待收到SYN|ACK并进入ESTABLISHED
					if(MyNet[i].Net_Type == TCP_CLIENT)
					{
						if(MyNet[i].Re_Sent < 3)
						{
							//超时后重发SYN
							MyNet[i].Re_Sent++;
							Send_TCP_Bag(&MyNet[i],TCPFLG_SYN,NULL,0);
						}
						else
						{
							//重发超过3次后服务器无应答，回到CLOSED状态
//							MyNet[i].Cur_Stat = TCP_CLOSED;
							MyNet[i].Cur_Stat = CLOSE;
						}
					}
				}
			}
			break;

			case TCP_ESTABLISHED:
			{
				if(MyNet[i].Cur_Stat != MyNet[i].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("Socket(%d) STATE TCP ESTABLISHED ENTRY\r\n",i);		
					MyNet[i].Pre_Stat = MyNet[i].Cur_Stat;	
					MyNet[i].Time_Count = MyIP_GetNowTime();		//获取当前时间
					MyNet[i].Re_Sent = 0;								//重发次数清0
					MyNet[i].TCP_WaitTime = TCP_KEEPALIVE_TIME;						//tcp_keepalive_time（开启keepalive的闲置时长）
				}
				if(MyNet[i].Net_Flg.reg.KeepAlive)
				{
					//有收发数据的话，重新计时
					if(MyNet[i].Net_Flg.reg.Data_Sent)						//连接有发送数据后
					{
						MyNet[i].Net_Flg.reg.Data_Sent = 0;
						MyNet[i].Time_Count = MyIP_GetNowTime();	
						MyNet[i].Re_Sent = 0;								//重发次数清0
						MyNet[i].TCP_WaitTime = TCP_KEEPALIVE_TIME;						//tcp_keepalive_time（开启keepalive的闲置时长）
						break;
					}
					else if(MyNet[i].Net_Flg.reg.Data_Recv)	
					{
						MyNet[i].Net_Flg.reg.Data_Recv = 0;
						MyNet[i].Time_Count = MyIP_GetNowTime();
						MyNet[i].Re_Sent = 0;								//重发次数清0
						MyNet[i].TCP_WaitTime = TCP_KEEPALIVE_TIME;						//tcp_keepalive_time（开启keepalive的闲置时长）
						break;
					}

					//超过设定时间没有数据收发，开始心跳探测
					if(MyIP_GetElapsedTime(MyNet[i].Time_Count) >= MyNet[i].TCP_WaitTime)
					{
						MyNet[i].TCP_WaitTime = TCP_KEEPALIVE_INTVL;										//tcp_keepalive_intvl（keepalive探测包的发送间隔）
						MyNet[i].Time_Count = MyIP_GetNowTime();
						if(MyNet[i].Re_Sent < TCP_KEEPALIVE_PROBES)							//tcp_keepalive_probes（如果对方不予应答，探测包的发送次数）
						{
							//超时后重发keepalive
							MyNet[i].Re_Sent++;
							MyNet[i].TCP_Mark--;
							Send_TCP_Bag(&MyNet[i],TCPFLG_ACK,NULL,0);
	//						MyPrintf("sent heartbeat\r\n");
						}
						else
						{
							//重发超过5次后对方无应答，回到CLOSED状态
//							MyNet[i].Cur_Stat = TCP_CLOSED;
							MyNet[i].Cur_Stat = CLOSE;
	//						MyPrintf("connect error\r\n");
						}
					}
				}
			}
			break;

			case TCP_FINWAIT1:
			{
				if(MyNet[i].Cur_Stat != MyNet[i].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("Socket(%d) STATE TCP FINWAIT1 ENTRY\r\n",i);		
					MyNet[i].Pre_Stat = MyNet[i].Cur_Stat;	
					MyNet[i].Time_Count = MyIP_GetNowTime();		//获取当前时间
					MyNet[i].Re_Sent = 0;							//重发次数清0
				}
				//客户端发出FIN|ACK后需等待服务器返回ACK
				if(MyIP_GetElapsedTime(MyNet[i].Time_Count) >= 2)
				{
					MyNet[i].Time_Count = MyIP_GetNowTime();
					//等待收到ACK或者FIN|ACK并进入FINWAIT1或ESTABLISHED
					if(MyNet[i].Net_Type == TCP_CLIENT)
					{
						if(MyNet[i].Re_Sent < 6)
						{
							//超时后重发FIN|ACK
							MyNet[i].Re_Sent++;
							Send_TCP_Bag(&MyNet[i],(TCPFLG_FIN|TCPFLG_ACK),NULL,0);
						}
						else
						{
							//重发超过3次后服务器无应答，回到CLOSED状态
							Send_TCP_Bag(&MyNet[i],(TCPFLG_RST|TCPFLG_ACK),NULL,0);
//							MyNet[i].Cur_Stat = TCP_CLOSED;
							MyNet[i].Cur_Stat = CLOSE;
						}
					}
				}

			}
			break;

			case TCP_FINWAIT2:
			{
				if(MyNet[i].Cur_Stat != MyNet[i].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("Socket(%d) STATE TCP FINWAIT2 ENTRY\r\n",i);		
					MyNet[i].Pre_Stat = MyNet[i].Cur_Stat;	
					MyNet[i].Time_Count = MyIP_GetNowTime();		//获取当前时间
					MyNet[i].Re_Sent = 0;							//重发次数清0
				}
				//客户端进入FINWAIT2状态后要等待服务器发回的FIN|ACK
				//此时服务器已经返回了ACK
				if(MyIP_GetElapsedTime(MyNet[i].Time_Count) >= 2)
				{
					MyNet[i].Time_Count = MyIP_GetNowTime();
					if(MyNet[i].Net_Type == TCP_CLIENT)
					{
						//直接关闭客户端回到CLOSED状态
//						MyNet[i].Cur_Stat = TCP_CLOSED;
						MyNet[i].Cur_Stat = CLOSE;
					}
				}
			}
			break;

			case TCP_CLOSING:
			{
				if(MyNet[i].Cur_Stat != MyNet[i].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("Socket(%d) STATE TCP CLOSING ENTRY\r\n",i);		
					MyNet[i].Pre_Stat = MyNet[i].Cur_Stat;	
					MyNet[i].Time_Count = MyIP_GetNowTime();		//获取当前时间
					MyNet[i].Re_Sent = 0;							//重发次数清0
				}
				//客户端进入CLOSING状态后需等待服务器返回的ACK然后关闭客户端连接
				if(MyIP_GetElapsedTime(MyNet[i].Time_Count) >= 2)
				{
					MyNet[i].Time_Count = MyIP_GetNowTime();
					if(MyNet[i].Net_Type == TCP_CLIENT)
					{
						if(MyNet[i].Re_Sent < 3)
						{
							//超时后重发FIN|ACK
							MyNet[i].Re_Sent++;
							Send_TCP_Bag(&MyNet[i],(TCPFLG_FIN|TCPFLG_ACK),NULL,0);
						}
						else
						{
							//重发超过3次后服务器无应答，回到CLOSED状态
//							MyNet[i].Cur_Stat = TCP_CLOSED;
							MyNet[i].Cur_Stat = CLOSE;
						}
					}
				}
			}
			break;

			case TCP_TIMEWAIT:
			{
				if(MyNet[i].Cur_Stat != MyNet[i].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("Socket(%d) STATE TCP TIMEWAIT ENTRY\r\n",i);		
					MyNet[i].Pre_Stat = MyNet[i].Cur_Stat;	
					MyNet[i].Time_Count = MyIP_GetNowTime();		//获取当前时间
					MyNet[i].Re_Sent = 0;							//重发次数清0
				}
				//客户端进入TIMEWAIT状态后等待10s，然后进入关闭状态
				//因为在TIMEWAIT状态下仍然可能收到对方的FIN需要进行应答（对方没有收到我的ACK，又发送了一遍FIN|ACK）
				if(MyIP_GetElapsedTime(MyNet[i].Time_Count) >= 10)
				{
//					MyNet[i].Cur_Stat = TCP_CLOSED;
					MyNet[i].Cur_Stat = CLOSE;
				}
			}
			break;

			case TCP_CLOSEWAIT:
			{
				if(MyNet[i].Cur_Stat != MyNet[i].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("Socket(%d) STATE TCP CLOSEWAIT ENTRY\r\n",i);		
					MyNet[i].Pre_Stat = MyNet[i].Cur_Stat;	
					MyNet[i].Time_Count = MyIP_GetNowTime();		//获取当前时间
					MyNet[i].Re_Sent = 0;							//重发次数清0
				}
				//如果自己是服务器，并且主动断开连接的话，在此状态下要等对方返回ACK 和 FIN|ACK，然后进入CLOSE
				if(MyNet[i].Net_Type == TCP_SERVER)
				{
					if(MyIP_GetElapsedTime(MyNet[i].Time_Count) >= 3)	//计时超过两秒
					{
						MyNet[i].Cur_Stat = CLOSE;
					}
				}
			}
			break;

			case TCP_LASTASK:
			{
				if(MyNet[i].Cur_Stat != MyNet[i].Pre_Stat)
				{
					NETSTATE_DEBUGOUT("Socket(%d) STATE TCP LASTASK ENTRY\r\n",i);		
					MyNet[i].Pre_Stat = MyNet[i].Cur_Stat;	
					MyNet[i].Time_Count = MyIP_GetNowTime();		//获取当前时间
					MyNet[i].Re_Sent = 0;							//重发次数清0
				}
				//该状态下，服务器发送了FIN|ACK
				//并等待收到ASK并进入CLOSED
				if(MyIP_GetElapsedTime(MyNet[i].Time_Count) >= 2)	//计时超过两秒
				{
					MyNet[i].Time_Count = MyIP_GetNowTime();
					
					if(MyNet[i].Net_Type == TCP_SERVER)
					{
						if(MyNet[i].Re_Sent < 2)
						{
							//超时后重发FIN|ACK
							MyNet[i].Re_Sent++;
							Send_TCP_Bag(&MyNet[i],(TCPFLG_FIN|TCPFLG_ACK),NULL,0);
						}
						else
						{
							//重发超过3次后回到CLOSED状态
							Send_TCP_Bag(&MyNet[i],(TCPFLG_RST|TCPFLG_ACK),NULL,0);
							MyNet[i].Cur_Stat = CLOSE;
						}
					}
				}
				
			}
			break;
			
			default:
			{
			}
			break;
		}
	}
}

