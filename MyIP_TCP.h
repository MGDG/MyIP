/**
  ******************************************************************************
  * @file    MyIP_TCP.h
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   TCP数据包打包
  ******************************************************************************
 **/
#ifndef _MYIP_TCP_H
#define _MYIP_TCP_H

#include "MyIP_TCPIP.h"

#define TCPFLG_URG ((uint8_t)0x20)		//紧急指针有效
#define TCPFLG_ACK ((uint8_t)0x10)		//确认序号有效
#define TCPFLG_PSH ((uint8_t)0x08)		//表示有数据传输，接收方应该尽快将这个报文段交给应用层
#define TCPFLG_RST ((uint8_t)0x04)		//重建连接
#define TCPFLG_SYN ((uint8_t)0x02)		//同步序号用来发起一个连接
#define TCPFLG_FIN ((uint8_t)0x01)		//发端完成发送任务


uint8_t Send_TCP_Bag(LINKSTRUCT *node,uint8_t TCP_Flag,const uint8_t *data,uint16_t len);
uint8_t TCP_Data_Process(const uint8_t *data,uint16_t len);

#endif
