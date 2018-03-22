/**
  ******************************************************************************
  * @file    MyIP_IP.h
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   IP数据包打包
  ******************************************************************************
 **/
#ifndef _MYIP_IP_H
#define _MYIP_IP_H
#include "MyIP_TCPIP.h"



/**
  * @brief	IP 首部填充
  * @param	*node：连接
  * @param	IP_Type：IP数据报类型0 UDP,1 TCP,2 ICMP
  * @param	IP_len：IP数据报长度(IP首部+TCP或UDP或ICMP首部+数据),20+8+UDP_len,20+20+TCP_Len,20+40+ICMP_Len,

  * @return	bool	
  * @remark		
  */
bool IP_Head_Pack(LINKSTRUCT *node,const uint8_t *Re_IP,uint8_t IP_Type,uint16_t IP_len);


bool IP_Head_Pack_Ping(LINKSTRUCT *node,uint16_t IP_len,const uint8_t *data);


uint8_t IP_Data_Process(const uint8_t *data,uint16_t len);

#endif
