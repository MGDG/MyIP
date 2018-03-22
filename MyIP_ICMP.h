/**
  ******************************************************************************
  * @file    MyIP_ICMP.h
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   
  ******************************************************************************
 **/
#ifndef _MYIP_ICMP_H
#define _MYIP_ICMP_H

#include "MyIP_TCPIP.h"

void MyIP_Ping(const uint8_t *Re_IP);
//uint8_t Send_Ping_Bag(LINKSTRUCT *node,const uint8_t *Re_IP);
uint8_t ICMP_Data_Process(const uint8_t *data,uint16_t len);

#endif
