/**
  ******************************************************************************
  * @file    MyIP_UDP.h
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   
  ******************************************************************************
 **/
#ifndef _MYIP_UDP_H
#define _MY_UDP_H
#include "MyIP_TCPIP.h"

typedef struct
{
	uint8_t  Re_IP[4];				//远程IP
	uint8_t  Re_MAC[6];				//远程MAC
	uint16_t Lc_Port;				//本地端口
	uint16_t Re_Port;				//远程端口
}UDPSTRUCT;

uint8_t Send_UDP_Bag(LINKSTRUCT *node,const UDPSTRUCT *udp,const uint8_t *DATA,uint16_t len);
void UDP_Config(LINKSTRUCT *node,const uint8_t *Re_IP,uint16_t Re_PORT,uint16_t Lc_PORT);
uint8_t UDP_Data_Process(const uint8_t *data,uint16_t len);
void UDP_Send(LINKSTRUCT *node,const uint8_t *ip,uint16_t RePort,const uint8_t *data,uint16_t len);

#endif
