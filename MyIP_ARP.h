/**
  ******************************************************************************
  * @file    MyIP_ARP.h
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   
  ******************************************************************************
 **/
#ifndef _MYIP_ARP_H
#define _MYIP_ARP_H

#include "MyIP_TCPIP.h"

bool ARPCache_Read(const uint8_t *ip,uint8_t *OutMAC);
bool ARPCache_Write(const uint8_t *ip,const uint8_t *MAC);
bool ARPCache_Delete(const uint8_t *ip);
void MyIP_ARPCacheRefresh(void);
void ARPCache_Printf(void);

void ARP_Request(const uint8_t *Re_IP);

uint8_t ARP_Data_Process(const uint8_t *data,uint16_t len);

#endif
