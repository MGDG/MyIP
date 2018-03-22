/**
  ******************************************************************************
  * @file    MyIP_Enthernet.c
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   
  ******************************************************************************
 **/
#include "MyIP_Enthernet.h"

/**
  * @brief	Enthernet 首部填充
  * @param	*node：连接
  * @param	*remac： 目的地MAC
  * @param	*lcmac： 本地MAC
  * @param	type：00 IP包  06 ARP包

  * @return	bool	
  * @remark		
  */
bool EN_Head_Pack(LINKSTRUCT *node,const uint8_t *remac,const uint8_t *lcmac,uint8_t type)
{
	if(node == NULL)
		return false;
	if(remac == NULL || lcmac == NULL)
		return false;
	if(type!=0 && type!=6)				//0x00;//IP包		0x06;//ARP包
		return false;

	memcpy(node->EN_Head,remac,6);			//填充目的MAC
	memcpy(node->EN_Head+6,lcmac,6);			//填充本地MAC
	node->EN_Head[12] = 0x08;
	node->EN_Head[13] = type;
	
	return true;
}
