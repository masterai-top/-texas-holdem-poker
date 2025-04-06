#ifndef __LOGIN_LOGCOMM_H__
#define __LOGIN_LOGCOMM_H__

//
#include <util/tc_logger.h>
#include "servant/RemoteLogger.h"

//
using namespace tars;

//
#define ROLLLOG(level) (LOG->level() << "[" << __FILE__ << ":" << __LINE__ << ":" << __FUNCTION__ << "] ")
#define ROLLLOG_DEBUG (ROLLLOG(debug))
#define ROLLLOG_INFO (ROLLLOG(info))
#define ROLLLOG_WARN (ROLLLOG(warn))
#define ROLLLOG_ERROR (ROLLLOG(error))

#define FUNC_ENTRY(in) (ROLLLOG(debug) << ">>>> Enter " << __FUNCTION__ << "() in(" << in << ")" << endl)
#define FUNC_EXIT(out, ret) (ROLLLOG(debug) << "<<<< Exit " << __FUNCTION__ << "() out[" << out << "], ret = " << ret << endl)

#define FDLOG_ERROR (FDLOG("error") << __FILE__ << ":" << __LINE__ << ":" << __FUNCTION__ << "|")
#define FDLOG_EXCEPT (FDLOG("except") << __FILE__ << ":" << __LINE__ << ":" << __FUNCTION__ << "|")

//配置信息
#define FDLOG_CONFIG_INFO (FDLOG("config_info") << "|")

//用户注册日志
// #define ACCOUNT_REG_LOG_TOPIC "account_reg_log"
// #define FDLOG_ACCOUNT_REG_LOG (FDLOG("account_reg_log") << "|")

//
// #define FDLOG_INIT_FORMAT(x, y, z) (TarsTimeLogger::getInstance()->initFormatWithType<LogByMinute>(x, y, z))
// #define FDLOG_ACCOUNT_REG_LOG_FORMAT (FDLOG_INIT_FORMAT("account_reg_log", "%Y%m%d%H%M", 5))

//接口性能边界值
#define COST_MS 100

//函数调用消耗时间
#define FUNC_COST_MS(consumStartMs) { long __costTime__ = (TNOWMS) - (consumStartMs);\
 if (__costTime__ > 3) {ROLLLOG_DEBUG << "scheduler consumTime: " << __costTime__ << endl;} }

#endif
