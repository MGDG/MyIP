/**
  ******************************************************************************
  * @file    MyIP_Enthernet.h
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   
  ******************************************************************************
 **/
#ifndef _MYIP_ENTHERNET_H
#define _MYIP_ENTHERNET_H

#include "MyIP_TCPIP.h"

/**
  * @brief	Enthernet 首部填充
  * @param	*node：连接
  * @param	*remac： 目的地MAC
  * @param	*lcmac： 本地MAC
  * @param	type：00 IP包  06 ARP包

  * @return	bool	
  * @remark		
  */
bool EN_Head_Pack(LINKSTRUCT *node,const uint8_t *remac,const uint8_t *lcmac,uint8_t type);





#endif
