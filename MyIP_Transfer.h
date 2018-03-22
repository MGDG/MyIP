/**
  ******************************************************************************
  * @file    MyIP_Transfer.h
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   网卡数据传输
  ******************************************************************************
 **/
#ifndef _MYIP_TRANSFER_H
#define _MYIP_TRANSFER_H

#include "MyIP_TCPIP.h"

uint16_t MyIP_PacketReceive(uint8_t* packet,uint16_t maxlen);
void ARP_Packet_Send(const uint8_t *EN_Head,const uint8_t *ARP_Head);
void UDP_Packet_Send(const uint8_t *EN_Head,const uint8_t *IP_Head,const uint8_t *UDP_Head,const uint8_t *DATA,uint16_t len);
void TCP_Packet_Send(const uint8_t *EN_Head,const uint8_t *IP_Head,const uint8_t *TCP_Head,const uint8_t *DATA,uint16_t len);
void ICMP_Ping_Packet_Send(const uint8_t *EN_Head,const uint8_t *IP_Head,const uint8_t *ICMP_Head,uint16_t ICMP_len);

void UDP_Data_Recev(uint16_t sockfd,const uint8_t *data,uint16_t len);
uint16_t TCP_Data_Recev(uint16_t sockfd,const uint8_t *data,uint16_t len);

#endif
