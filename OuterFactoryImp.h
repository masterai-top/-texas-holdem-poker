#ifndef _OUTER_FACTORY_IMP_H_
#define _OUTER_FACTORY_IMP_H_

#include <string>
#include <map>
#include "servant/Application.h"
#include "globe.h"
#include "OuterFactory.h"
#include <wbl/regex_util.h>
#include <wbl/regex_util.h>
#include <maxminddb.h>
#include "ConfigServant.h"
#include "DBAgentServant.h"
#include "HallServant.h"
#include "GlobalServant.h"
#include "PushServant.h"
#include "GameRecordServant.h"
#include "Log2DBServant.h"
#include "util/tc_hash_fun.h"

//
using namespace tars;
using namespace config;
using namespace hall;
using namespace dataproxy;
using namespace dbagent;
using namespace global;

//时区
#define ONE_DAY_TIME (24 * 60 * 60)
#define ZONE_TIME_OFFSET (8 * 60 * 60)

//
class OuterFactoryImp;

typedef TC_AutoPtr<OuterFactoryImp> OuterFactoryImpPtr;

/**
* weixin配置
*/
typedef struct _TWeixinConfig
{
    string appid;      //#APPID
    string app_secret; //#应用App秘钥
} WeixinConfig;

/**
 * 短信平台配置
 */
typedef struct _TSMSConfig
{
    //是否开放
    int isOpen;
    //发送地址
    std::string sendURL;
    //平台帐号
    std::string account;
    //平台密码
    std::string password;
    //短信模板
    std::string content;
    //应用ID
    std::string appid;
} SMSConfig;

struct EmailConfig
{
    //发件邮箱
    std::string from_email;
    //抄送邮箱
    std::string cc_mail;
    //登录密码
    std::string passwd;
    //邮件服务器
    std::string smtp_server;
    //邮件主题
    std::string subject;
    //邮件模板
    std::string content;
    //海外邮件主题
    std::string subject_oversea;
    //海外邮件模板
    std::string content_oversea;
};

/**
 * 玩家初始化财富
 */
typedef struct _UserInitWealth
{
    long gold;      //筹码
    long diamond;   //钻石
    long score;     //积分
    long ticketNum; //奖券
    long bindgold;//绑定奖励
} UserInitWealth;

class OuterFactoryImp : public OuterFactory
{
private:
    OuterFactoryImp();
    ~OuterFactoryImp();

    //
    friend class LoginServantImp;
    //
    friend class LoginServer;

public:
    //框架中用到的outer接口(不能修改):
    const OuterProxyFactoryPtr &getProxyFactory() const
    {
        return _pProxyFactory;
    }
    //
    tars::TC_Config &getConfig() const
    {
        return *_pFileConf;
    }

public:
    //读取所有配置
    void load();
    //代理配置
    void readPrxConfig();
    //打印代理配置
    void printPrxConfig();
    //微信配置
    void readWeixinConfig();
    //打印微信配置
    void printWeixinConfig();
    //获取微信配置
    const WeixinConfig &getWeixinConfig();
    //获取国内短信平台配置
    const SMSConfig &getSMSConfig();
    //获取海外通用短信平台配置
    const SMSConfig &getSMSConfigOversea();
    //获取海外印度短信平台配置
    const SMSConfig &getSMSConfigIndia();
    //google配置
    void readGoogleConfig();
    //打印google配置
    void printGoogleConfig();
    //取goole配置
    const std::vector<std::string> &getGoogleConfig();
    //facebook配置
    void readFackbookConfig();
    //打印facebook配置
    void printFackbookConfig();
    //取facebook配置
    const std::string getAccessFackbookToken();
    //获取FB认证地址
    const std::string getAuthFackbookUrl();
    //获取FB信息地址
    const std::string getFackbookInfoUrl();
    //获取代理开关配置
    void readAgentOpenConfig();
    //打印代理开关信息
    void printAgentOpenConfig();
    //获取代理开关信息
    const bool getAgentOpenConfig();
    //读取短信平台配置
    void reloadSMSConfig();
    //加载玩家初始化财富配置
    void readUserInitWealth();
    //打印玩家初始化财富配置
    void printUserInitWealth();
    //获取玩家初始化财富配置
    const UserInitWealth &getUserInitWealth(int type = 0);
    //加载IP库配置
    void readGeoLite();
    //打印IP库配置
    void printGeoLite();
    //获取IP库配置
    const std::string &getGeoLite();
    //加载邮件模板配置
    void reloadEmailConfig();
    //获取邮件模板配置
    const EmailConfig &getEmailConfig();

private:
    //
    void createAllObject();
    //
    void deleteAllObject();

public:
    //游戏配置服务代理
    const ConfigServantPrx getConfigServantPrx();
    //广场服务代理
    const HallServantPrx getHallServantPrx(const long uid);
    //广场服务代理
    const HallServantPrx getHallServantPrx(const string key);
    //公共服务代理
    const GlobalServantPrx getGlobalServantPrx(const long uid);
    //PushServer的对象名称
    const push::PushServantPrx getPushServerPrx(const long uid);
    //数据库代理服务代理
    const DBAgentServantPrx getDBAgentServantPrx(const int64_t uid);
    //数据库代理服务代理
    const DBAgentServantPrx getDBAgentServantPrx(const string key);
    //游戏记录服务代理
    const gamerecord::GameRecordServantPrx getGameRecordPrx(const long uid);
    //日志入库服务代理
    const DaqiGame::Log2DBServantPrx getLog2DBServantPrx(const long uid);

public:
    //初始化GeoIP
    int initializeGeoIP();
    //释放GeoIP
    int destoryGeoIP();
    //查找areaid
    int lookupAreaID(const string &ipaddr, string &countryCode);
    // 读取区域ID
    void readAreaID();
    //打印区域信息
    void printAreaID();
    //获取区域标识
    const map<string, int> &getAreaIDMap();
    //测试geoip
    void testGeoIP();

public:
    //
    void asyncLog2DB(const int64_t uid, const short type, const std::vector<string> &fields);

public:
    //格式化时间
    string GetTimeFormat();
    //格式化自定义时间
    string GetCustomTimeFormat(int time);
    //获得时间秒数
    int GetTimeTick(const string &str);

private:
    //拆分字符串成整形
    int splitInt(string szSrc, vector<int> &vecInt);
    //读写锁，防止脏读
    wbl::ReadWriteLocker m_rwlock;

private:
    //框架用到的共享对象(不能修改):
    tars::TC_Config *_pFileConf;
    //
    OuterProxyFactoryPtr _pProxyFactory;

private:
    //游戏配置服务
    std::string _ConfigServantObj;
    //
    ConfigServantPrx _ConfigServerPrx;
    //用户信息服务
    std::string _HallServantObj;
    //
    HallServantPrx _HallServerPrx;
    //区域查询服务
    std::string _GlobalServantObj;
    //
    GlobalServantPrx _GlobalServerPrx;
    //pushServer的对象名称
    string _sPushServantObj;
    //
    push::PushServantPrx _pushServerPrx;
    //数据库代理服务
    std::string _DBAgentServantObj;
    //
    DBAgentServantPrx _DBAgentServerPrx;
    //游戏记录服务
    string _sGameRecordObj;
    //
    gamerecord::GameRecordServantPrx _RecordServerPrx;
    //日志入库服务
    std::string _Log2DBServantObj;
    //
    DaqiGame::Log2DBServantPrx _Log2DBServerPrx;

private:
    //
    WeixinConfig weixinConfig;
    //国内短信平台配置
    SMSConfig smsConfig;
    //海外通用短信平台配置
    SMSConfig smsConfigOversea;
    //海外印度短信平台配置
    SMSConfig smsConfigIndia;
    //邮件模板配置
    EmailConfig emailConfig;
    //
    std::vector<std::string> vgoogleAppId;
    //
    std::string accessFackbookToken;
    //
    std::string authFackbookUrl;
    //
    std::string getFackbookUserInfoUrl;
    //
    bool agentOpen;
    //
    MMDB_s mmdb;
    //
    std::map<string, int> m_mapAreaID;
    //
    map<int, UserInitWealth> m_userInitWealth;
    //
    std::string strGetLitePath;
};

////////////////////////////////////////////////////////////////////////////////
#endif
