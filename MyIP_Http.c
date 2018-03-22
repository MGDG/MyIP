/**
  ******************************************************************************
  * @file    MyIP_Http.c
  * @author  mgdg
  * @version V1.0.0
  * @date    2018-02-28
  * @brief   
  ******************************************************************************
 **/
#include "MyIP_Http.h"
  
#define HTTP_DEBUGOUT(...)	TCPDEBUGOUT(__VA_ARGS__)


/**
  * @brief	判断远程ip是否为局域网
  * @param	*node： 连接

  * @return	bool	
  * @remark	true 内网， false 外网
  */
