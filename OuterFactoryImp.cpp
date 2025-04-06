#include <sstream>
#include "LogComm.h"
#include "OuterFactoryImp.h"
#include "LoginServer.h"
#include "util/tc_hash_fun.h"

using namespace wbl;

OuterFactoryImp::OuterFactoryImp() : _pFileConf(NULL), agentOpen(false)
{
    createAllObject();
}

OuterFactoryImp::~OuterFactoryImp()
{
    deleteAllObject();
}

//
void OuterFactoryImp::deleteAllObject()
{
    //销毁IP查询
    destoryGeoIP();

    if (_pFileConf)
    {
        delete _pFileConf;
        _pFileConf = NULL;
    }
}

//
void OuterFactoryImp::createAllObject()
{
    try
    {
        //
        deleteAllObject();

        //本地配置文件
        _pFileConf = new tars::TC_Config();
        if (!_pFileConf)
        {
            ROLLLOG_ERROR << "create config parser fail, ptr null." << endl;
            terminate();
        }

        //tars代理Factory,访问其他tars接口时使用
        _pProxyFactory = new OuterProxyFactory();
        if ((long int)NULL == _pProxyFactory)
        {
            ROLLLOG_ERROR << "create outer proxy factory fail, ptr null." << endl;
            terminate();
        }

        LOG_DEBUG << "init proxy factory succ." << endl;
        // FDLOG_ACCOUNT_REG_LOG_FORMAT;

        //读取所有配置
        load();

        // //初始化GeoIP
        // int iRet = initializeGeoIP();
        // if (iRet != 0)
        // {
        //     ROLLLOG_ERROR << "initialize geoip fail, iRet: " << iRet << endl;
        //     terminate();
        // }
    }
    catch (TC_Exception &ex)
    {
        LOG->error() << ex.what() << endl;
    }
    catch (exception &e)
    {
        LOG->error() << e.what() << endl;
    }
    catch (...)
    {
        LOG->error() << "unknown exception." << endl;
    }

    return;
}

//读取所有配置
void OuterFactoryImp::load()
{
    __TRY__

    //拉取远程配置
    g_app.addConfig(ServerConfig::ServerName + ".conf");

    wbl::WriteLocker lock(m_rwlock);

    _pFileConf->parseFile(ServerConfig::BasePath + ServerConfig::ServerName + ".conf");
    LOG_DEBUG << "init config file succ:" << ServerConfig::BasePath + ServerConfig::ServerName + ".conf" << endl;

    //代理配置
    readPrxConfig();
    printPrxConfig();

    //微信配置
    readWeixinConfig();
    printWeixinConfig();

    //google配置
    readGoogleConfig();
    printGoogleConfig();

    //facebook配置
    readFackbookConfig();
    printFackbookConfig();

    //本地代理开关
    readAgentOpenConfig();
    printAgentOpenConfig();

    //短信通道配置
    reloadSMSConfig();

    //邮件模板配置
    reloadEmailConfig();

    // //读取匹配配置
    // readAreaID();
    // printAreaID();

    //玩家初始化财富
    readUserInitWealth();
    printUserInitWealth();

    // //初始IP库配置
    // readGeoLite();
    // printGeoLite();

    __CATCH__
}

//代理配置
void OuterFactoryImp::readPrxConfig()
{
    _ConfigServantObj = (*_pFileConf).get("/Main/Interface/ConfigServer<ProxyObj>", "");
    _DBAgentServantObj = (*_pFileConf).get("/Main/Interface/DBAgentServer<ProxyObj>", "");
    _HallServantObj = (*_pFileConf).get("/Main/Interface/HallServer<ProxyObj>", "");
    _GlobalServantObj = (*_pFileConf).get("/Main/Interface/GlobalServer<ProxyObj>", "");
    _sPushServantObj = (*_pFileConf).get("/Main/Interface/PushServer<ProxyObj>", "");
    _sGameRecordObj = (*_pFileConf).get("/Main/Interface/GameRecordServer<ProxyObj>", "");
    _Log2DBServantObj = (*_pFileConf).get("/Main/Interface/Log2DBServer<ProxyObj>", "");
}

//打印代理配置
void OuterFactoryImp::printPrxConfig()
{
    FDLOG_CONFIG_INFO << "_ConfigServantObj ProxyObj:" << _ConfigServantObj << endl;
    FDLOG_CONFIG_INFO << "_DBAgentServantObj ProxyObj:" << _DBAgentServantObj << endl;
    FDLOG_CONFIG_INFO << "_HallServantObj ProxyObj:" << _HallServantObj << endl;
    FDLOG_CONFIG_INFO << "_GlobalServantObj ProxyObj:" << _GlobalServantObj << endl;
    FDLOG_CONFIG_INFO << "_sPushServantObj ProxyObj: " << _sPushServantObj << endl;
    FDLOG_CONFIG_INFO << "_sGameRecordObj ProxyObj: " << _sGameRecordObj << endl;
    FDLOG_CONFIG_INFO << "_Log2DBServantObj ProxyObj : " << _Log2DBServantObj << endl;
}

//游戏配置服务代理
const ConfigServantPrx OuterFactoryImp::getConfigServantPrx()
{
    if (!_ConfigServerPrx)
    {
        _ConfigServerPrx = Application::getCommunicator()->stringToProxy<ConfigServantPrx>(_ConfigServantObj);
        ROLLLOG_DEBUG << "Init _ConfigServantObj succ, _ConfigServantObj:" << _ConfigServantObj << endl;
    }

    return _ConfigServerPrx;
}

//广场信息服务代理
const HallServantPrx OuterFactoryImp::getHallServantPrx(const long uid)
{
    if (!_HallServerPrx)
    {
        _HallServerPrx = Application::getCommunicator()->stringToProxy<HallServantPrx>(_HallServantObj);
        ROLLLOG_DEBUG << "Init _HallServantObj succ, _HallServantObj:" << _HallServantObj << endl;
    }

    if (_HallServerPrx)
    {
        return _HallServerPrx->tars_hash(uid);
    }

    return NULL;
}

//广场信息服务代理
const HallServantPrx OuterFactoryImp::getHallServantPrx(const string key)
{
    if (!_HallServerPrx)
    {
        _HallServerPrx = Application::getCommunicator()->stringToProxy<HallServantPrx>(_HallServantObj);
        ROLLLOG_DEBUG << "Init _HallServantObj succ, _HallServantObj:" << _HallServantObj << endl;
    }

    if (_HallServerPrx)
    {
        return _HallServerPrx->tars_hash(tars::hash<string>()(key));
    }

    return NULL;
}

//公共服务代理
const GlobalServantPrx OuterFactoryImp::getGlobalServantPrx(const long uid)
{
    if (!_GlobalServerPrx)
    {
        _GlobalServerPrx = Application::getCommunicator()->stringToProxy<GlobalServantPrx>(_GlobalServantObj);
        ROLLLOG_DEBUG << "Init _GlobalServantObj succ, _GlobalServantObj:" << _GlobalServantObj << endl;
    }

    if (_GlobalServerPrx)
    {
        return _GlobalServerPrx->tars_hash(uid);
    }

    return NULL;
}

const push::PushServantPrx OuterFactoryImp::getPushServerPrx(const long uid)
{
    if (!_pushServerPrx)
    {
        _pushServerPrx = Application::getCommunicator()->stringToProxy<push::PushServantPrx>(_sPushServantObj);
        LOG_DEBUG << "Init _sPushServantObj succ, _sPushServantObj: " << _sPushServantObj << endl;
    }

    if (_pushServerPrx)
    {
        return _pushServerPrx->tars_hash(uid);
    }

    return NULL;
}

//数据库代理服务代理
const DBAgentServantPrx OuterFactoryImp::getDBAgentServantPrx(const int64_t uid)
{
    if (!_DBAgentServerPrx)
    {
        _DBAgentServerPrx = Application::getCommunicator()->stringToProxy<dbagent::DBAgentServantPrx>(_DBAgentServantObj);
        ROLLLOG_DEBUG << "Init _DBAgentServantObj succ, _DBAgentServantObj:" << _DBAgentServantObj << endl;
    }

    if (_DBAgentServerPrx)
    {
        return _DBAgentServerPrx->tars_hash(uid);
    }

    return NULL;
}

//数据库代理服务代理
const DBAgentServantPrx OuterFactoryImp::getDBAgentServantPrx(const string key)
{
    if (!_DBAgentServerPrx)
    {
        _DBAgentServerPrx = Application::getCommunicator()->stringToProxy<dbagent::DBAgentServantPrx>(_DBAgentServantObj);
        ROLLLOG_DEBUG << "Init _DBAgentServantObj succ, _DBAgentServantObj:" << _DBAgentServantObj << endl;
    }

    if (_DBAgentServerPrx)
    {
        return _DBAgentServerPrx->tars_hash(tars::hash<string>()(key));
    }

    return NULL;
}

//微信配置
void OuterFactoryImp::OuterFactoryImp::readWeixinConfig()
{
    weixinConfig.appid = (*_pFileConf).get("/Main/Weixin<appid>", "");
    weixinConfig.app_secret = (*_pFileConf).get("/Main/Weixin<app_secret>", "");
}

//打印微信配置
void OuterFactoryImp::OuterFactoryImp::printWeixinConfig()
{
    FDLOG_CONFIG_INFO << "weixin config, appid:" << weixinConfig.appid << ", app_secret: " << weixinConfig.app_secret << endl;
}

//获取微信配置
const WeixinConfig &OuterFactoryImp::getWeixinConfig()
{
    return weixinConfig;
}

//获取国内短信平台配置
const SMSConfig &OuterFactoryImp::getSMSConfig()
{
    return smsConfig;
}

//获取海外通用短信平台配置
const SMSConfig &OuterFactoryImp::getSMSConfigOversea()
{
    return smsConfigOversea;
}

//获取海外印度短信平台配置
const SMSConfig &OuterFactoryImp::getSMSConfigIndia()
{
    return smsConfigIndia;
}

//短信平台配置
void OuterFactoryImp::reloadSMSConfig()
{
    smsConfig.isOpen = S2I((*_pFileConf).get("/Main/SMS<isOpen>", "0"));
    smsConfig.sendURL = (*_pFileConf).get("/Main/SMS<sendUrl>", "");
    smsConfig.account = (*_pFileConf).get("/Main/SMS<account>", "");
    smsConfig.password = (*_pFileConf).get("/Main/SMS<password>", "");
    smsConfig.content = (*_pFileConf).get("/Main/SMS<content>", "");
    smsConfigOversea.sendURL = (*_pFileConf).get("/Main/SMS/Oversea<sendUrl>", "");
    smsConfigOversea.account = (*_pFileConf).get("/Main/SMS/Oversea<account>", "");
    smsConfigOversea.password = (*_pFileConf).get("/Main/SMS/Oversea<password>", "");
    smsConfigOversea.content = (*_pFileConf).get("/Main/SMS/Oversea<content>", "");
    smsConfigOversea.appid = (*_pFileConf).get("/Main/SMS/Oversea<appid>", "");
    smsConfigIndia.content = (*_pFileConf).get("/Main/SMS/India<content>", "");

    FDLOG_CONFIG_INFO << "smsConfig.isOpen:" << smsConfig.isOpen << endl;
    FDLOG_CONFIG_INFO << "smsConfig.sendURL:" << smsConfig.sendURL << endl;
    FDLOG_CONFIG_INFO << "smsConfig.account:" << smsConfig.account << endl;
    FDLOG_CONFIG_INFO << "smsConfig.password:" << smsConfig.password << endl;
    FDLOG_CONFIG_INFO << "smsConfig.content :" << smsConfig.content << endl;
    FDLOG_CONFIG_INFO << "smsConfigOversea.sendURL:" << smsConfigOversea.sendURL << endl;
    FDLOG_CONFIG_INFO << "smsConfigOversea.account:" << smsConfigOversea.account << endl;
    FDLOG_CONFIG_INFO << "smsConfigOversea.password:" << smsConfigOversea.password << endl;
    FDLOG_CONFIG_INFO << "smsConfigOversea.content :" << smsConfigOversea.content << endl;
    FDLOG_CONFIG_INFO << "smsConfigOversea.appid :" << smsConfigOversea.appid << endl;
    FDLOG_CONFIG_INFO << "smsConfigIndia.content :" << smsConfigIndia.content << endl;
}

//获取邮件模板配置
const EmailConfig &OuterFactoryImp::getEmailConfig()
{
    return emailConfig;
}

//邮件模板配置
void OuterFactoryImp::reloadEmailConfig()
{
    emailConfig.from_email = (*_pFileConf).get("/Main/Email<from_email>", "");
    emailConfig.cc_mail = (*_pFileConf).get("/Main/Email<cc_mail>", "");
    emailConfig.passwd = (*_pFileConf).get("/Main/Email<passwd>", "");
    emailConfig.smtp_server = (*_pFileConf).get("/Main/Email<smtp_server>", "");
    emailConfig.subject = (*_pFileConf).get("/Main/Email<subject>", "");
    emailConfig.content = (*_pFileConf).get("/Main/Email<content>", "");
    emailConfig.subject_oversea = (*_pFileConf).get("/Main/Email/Oversea<subject>", "");
    emailConfig.content_oversea = (*_pFileConf).get("/Main/Email/Oversea<content>", "");

    FDLOG_CONFIG_INFO << "emailConfig.from_email:" << emailConfig.from_email << endl;
    FDLOG_CONFIG_INFO << "emailConfig.cc_mail:" << emailConfig.cc_mail << endl;
    FDLOG_CONFIG_INFO << "emailConfig.passwd:" << emailConfig.passwd << endl;
    FDLOG_CONFIG_INFO << "emailConfig.smtp_server:" << emailConfig.smtp_server << endl;
    FDLOG_CONFIG_INFO << "emailConfig.subject:" << emailConfig.subject << endl;
    FDLOG_CONFIG_INFO << "emailConfig.content:" << emailConfig.content << endl;
    FDLOG_CONFIG_INFO << "emailConfig.subject_oversea:" << emailConfig.subject_oversea << endl;
    FDLOG_CONFIG_INFO << "emailConfig.content_oversea:" << emailConfig.content_oversea << endl;
}

//google配置
void OuterFactoryImp::OuterFactoryImp::readGoogleConfig()
{
    unsigned int AppIdNum = stoi((*_pFileConf).get("/Main/Google<AppIdNum>", ""));
    for (unsigned int i = 1; i <= AppIdNum; ++i)
    {
        std::string keyname = "/Main/Google<vAppId" + to_string(i) + ">";
        vgoogleAppId.push_back((*_pFileConf).get(keyname, ""));
    }
}

//打印google配置
void OuterFactoryImp::printGoogleConfig()
{
    ostringstream os;
    os << "google config, vAppIdd:  " << endl;
    for (auto appid : vgoogleAppId)
    {
        os << appid << endl;
    }

    FDLOG_CONFIG_INFO << os.str() << endl;
}

//取goole配置
const std::vector<std::string> &OuterFactoryImp::getGoogleConfig()
{
    return vgoogleAppId;
}

//facebook配置
void OuterFactoryImp::readFackbookConfig()
{
    accessFackbookToken = (*_pFileConf).get("/Main/Facebook<accessToken>", "");
    authFackbookUrl = (*_pFileConf).get("/Main/Facebook<authUrl>", "");
    getFackbookUserInfoUrl = (*_pFileConf).get("/Main/Facebook<getInfoUrl>", "");
}

//打印facebook配置
void OuterFactoryImp::printFackbookConfig()
{
    FDLOG_CONFIG_INFO << "facebook config, accessToken:" << accessFackbookToken << endl;
    FDLOG_CONFIG_INFO << "facebook config, authUrl:" << authFackbookUrl << endl;
    FDLOG_CONFIG_INFO << "facebook config, getInfoUrl:" << getFackbookUserInfoUrl << endl;
}

//取facebook配置
const std::string OuterFactoryImp::getAccessFackbookToken()
{
    return accessFackbookToken;
}
const std::string OuterFactoryImp::getAuthFackbookUrl()
{
    return authFackbookUrl;
}
const std::string OuterFactoryImp::getFackbookInfoUrl()
{
    return getFackbookUserInfoUrl;
}

//本地代理开关
void OuterFactoryImp::readAgentOpenConfig()
{
    string ret = (*_pFileConf).get("/Main/AgentOpen<open>", "");
    agentOpen = (ret == "1");
}

//
void OuterFactoryImp::printAgentOpenConfig()
{
    FDLOG_CONFIG_INFO << "tAgentOpen config, agentOpen:" << agentOpen << endl;
}

//
const bool OuterFactoryImp::getAgentOpenConfig()
{
    return agentOpen;
}

//获取玩家初始化财富配置
const UserInitWealth &OuterFactoryImp::getUserInitWealth(int type)
{
    auto it = m_userInitWealth.find(type);
    if (it != m_userInitWealth.end())
    {
        return it->second;
    }

    static UserInitWealth uiw;
    return uiw;
}

//加载玩家初始化财富
void OuterFactoryImp::readUserInitWealth()
{
    m_userInitWealth.clear();
    const vector<string> &vecDomain = (*_pFileConf).getDomainVector("/Main/UserInitWealth");
    int i = 0;
    for (auto &elemName : vecDomain)
    {
        i++;
        string path = string("/Main/UserInitWealth/") + elemName;

        UserInitWealth detail;
        detail.gold = S2L((*_pFileConf).get(path + "<Gold>", "0"));
        detail.diamond = S2L((*_pFileConf).get(path + "<Diamond>", "0"));
        detail.score = S2L((*_pFileConf).get(path + "<Score>", "0"));
        detail.ticketNum = S2L((*_pFileConf).get(path + "<TicketNum>", "0"));
        detail.bindgold = S2L((*_pFileConf).get(path + "<BindGold>", "0"));
        m_userInitWealth[i] = detail;
    }
}

//打印玩家初始化财富
void OuterFactoryImp::printUserInitWealth()
{
    FDLOG_CONFIG_INFO << "userInitWealth." << endl;
    for(auto item : m_userInitWealth)
    {
        FDLOG_CONFIG_INFO << "index: " << item.first << ", [ gold:" << item.second.gold << ",diamond:" << item.second.diamond
                          << ",socre:" << item.second.score << ",ticketNum:" << item.second.ticketNum << ", bindgold: "<< item.second.bindgold << " ]" << endl;
    }
}

//加载IP库配置
void OuterFactoryImp::readGeoLite()
{
    strGetLitePath = (*_pFileConf).get("/Main/GeoLite<path>", "");
}

//打印IP库配置
void OuterFactoryImp::printGeoLite()
{
    FDLOG_CONFIG_INFO << "strGetLitePath: " << strGetLitePath << endl;
}

//获取IP库配置
const std::string &OuterFactoryImp::getGeoLite()
{
    return strGetLitePath;
}

//格式化时间
string OuterFactoryImp::GetTimeFormat()
{
    string sFormat("%Y-%m-%d %H:%M:%S");
    time_t t = TNOW;
    auto pTm = localtime(&t);
    if (pTm == NULL)
        return "";

    //format
    char sTimeString[255] = "\0";
    strftime(sTimeString, sizeof(sTimeString), sFormat.c_str(), pTm);
    return string(sTimeString);
}

//格式化自定义时间
string OuterFactoryImp::GetCustomTimeFormat(int time)
{
    string sFormat("%Y-%m-%d %H:%M:%S");
    time_t t = time_t(time);
    auto pTm = localtime(&t);
    if (pTm == NULL)
        return "";

    char sTimeString[255] = "\0";
    strftime(sTimeString, sizeof(sTimeString), sFormat.c_str(), pTm);
    return string(sTimeString);
}

//获得时间秒数
int OuterFactoryImp::GetTimeTick(const string &str)
{
    if (str.empty())
        return 0;

    struct tm tm_time;
    string sFormat("%Y-%m-%d %H:%M:%S");
    strptime(str.c_str(), sFormat.c_str(), &tm_time);
    return mktime(&tm_time);
}

//拆分字符串成整形
int OuterFactoryImp::splitInt(string szSrc, vector<int> &vecInt)
{
    split_int(szSrc, "[ \t]*\\|[ \t]*", vecInt);
    return 0;
}

//游戏日志入库代理
const gamerecord::GameRecordServantPrx OuterFactoryImp::getGameRecordPrx(const long uid)
{
    if (!_RecordServerPrx)
    {
        _RecordServerPrx = Application::getCommunicator()->stringToProxy<gamerecord::GameRecordServantPrx>(_sGameRecordObj);
        LOG_DEBUG << "Init _sGameRecordObj succ, _sGameRecordObj: " << _sGameRecordObj << endl;
    }

    if (_RecordServerPrx)
    {
        return _RecordServerPrx->tars_hash(uid);
    }

    return NULL;
}

//日志入库服务代理
const DaqiGame::Log2DBServantPrx OuterFactoryImp::getLog2DBServantPrx(const long uid)
{
    if (!_Log2DBServerPrx)
    {
        _Log2DBServerPrx = Application::getCommunicator()->stringToProxy<DaqiGame::Log2DBServantPrx>(_Log2DBServantObj);
        ROLLLOG_DEBUG << "Init _Log2DBServantObj succ, _Log2DBServantObj : " << _Log2DBServantObj << endl;
    }

    if (_Log2DBServerPrx)
    {
        return _Log2DBServerPrx->tars_hash(uid);
    }

    return NULL;
}

//日志入库
void OuterFactoryImp::asyncLog2DB(const int64_t uid, const short type, const std::vector<string> &fields)
{
    DaqiGame::TLog2DBReq req;
    req.sLogType = type;
    req.vecLogData.push_back(fields);
    getLog2DBServantPrx(uid)->async_log2db(NULL, req);
}

//初始化GeoIP
int OuterFactoryImp::initializeGeoIP()
{
    int status = MMDB_open(strGetLitePath.c_str(), MMDB_MODE_MMAP, &mmdb);
    if (MMDB_SUCCESS == status)
        return 0;

    ROLLLOG_ERROR << "can't open file: " << strGetLitePath << ", err: " << MMDB_strerror(status) << endl;
    ROLLLOG_ERROR << "IO error: " << strerror(errno) << endl;
    return -1;
}

//查找areaid
int OuterFactoryImp::lookupAreaID(const string &ipaddr, string &countryCode)
{
    int gaiError;
    int mmdbError;
    auto result = MMDB_lookup_string(&mmdb, ipaddr.c_str(), &gaiError, &mmdbError);
    if (0 != gaiError)
    {
        ROLLLOG_DEBUG << "MMDB_lookup_string() failed(1), gaiError: " << gaiError << endl;
        return -1;
    }

    if (MMDB_SUCCESS != mmdbError)
    {
        ROLLLOG_DEBUG << "MMDB_lookup_string() failed(2), mmdbError: " << mmdbError << endl;
        return -2;
    }

    if (result.found_entry)
    {
        MMDB_entry_data_s entry_data;

        //获取国家名称(简体中文)
        //status = MMDB_get_value(&result.entry, &entry_data, "country", "names", "zh-CN", NULL);

        //获取国家简称(CN/AU/JP等)
        int status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);
        //获取城市名称(简体中文)
        //status = MMDB_get_value(&result.entry, &entry_data, "city", "names", "zh-CN", NULL);
        if (MMDB_SUCCESS != status)
            return -5;

        if (!entry_data.has_data)
            return -4;

        if (entry_data.type != MMDB_DATA_TYPE_UTF8_STRING)
            return -3;

        countryCode.assign(entry_data.utf8_string, 0, entry_data.data_size);
    }

    return 0;
}

//释放GeoIP
int OuterFactoryImp::destoryGeoIP()
{
    MMDB_close(&mmdb);
    return 0;
}

//测试geoip
void OuterFactoryImp::testGeoIP()
{
    string szfilename = ServerConfig::BasePath + "GeoLite2-Country.mmdb";
    const char *filename = szfilename.c_str();
    const char *ip_address = "114.240.52.162";

    MMDB_s mmdb;
    MMDB_entry_data_s entry_data;
    MMDB_lookup_result_s result;
    int gaiError, mmdbError;

    int status = MMDB_open(filename, MMDB_MODE_MMAP, &mmdb);
    if (MMDB_SUCCESS != status)
    {
        fprintf(stderr, "Can't open %s - %s\n", filename, MMDB_strerror(status));
        fprintf(stderr, "IO error: %s\n", strerror(errno));
        exit(1);
    }

    result = MMDB_lookup_string(&mmdb, ip_address, &gaiError, &mmdbError);
    if (0 != gaiError)
    {
        fprintf(stderr, "Error from getaddrinfo for %s - %s\n", ip_address, gai_strerror(gaiError));
        exit(2);
    }

    if (MMDB_SUCCESS != mmdbError)
    {
        fprintf(stderr, "Got an error from libmaxminddb: %s\n", MMDB_strerror(mmdbError));
        exit(3);
    }

    if (result.found_entry)
    {
        /* 获取国家名称(简体中文) */
        status = MMDB_get_value(&result.entry, &entry_data, "country", "names", "zh-CN", NULL);

        /* 获取国家简称(CN/AU/JP等) */
        //status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);

        /* 获取城市名称(简体中文) */
        //status = MMDB_get_value(&result.entry, &entry_data, "city", "names", "zh-CN", NULL);

        if (MMDB_SUCCESS == status)  /* MMDB_get_value 成功 */
        {
            if (entry_data.has_data)  /* 找到了想要的数据 */
            {
                if (entry_data.type == MMDB_DATA_TYPE_UTF8_STRING)
                {
                    /* entry_data.utf8_string 返回的不是null-terminated 字符串,需要根据长度自己截取数据 */
                    fwrite(entry_data.utf8_string, entry_data.data_size, 1, stdout);
                    printf("\n");
                }
                else
                {
                    printf("data_type = %d\n", entry_data.type);
                }
            }
            else
            {
                fprintf(stderr, "MMDB_get_value not found\n");
            }
        }
        else
        {
            fprintf(stderr, "MMDB_get_value failed,%s\n", MMDB_strerror(status));
        }
    }

    MMDB_close(&mmdb);
}

//获取区域标识
const map<string, int> &OuterFactoryImp::getAreaIDMap()
{
    return m_mapAreaID;
}

// 读取区域ID
void OuterFactoryImp::readAreaID()
{
    auto domainMap = (*_pFileConf).getDomainMap("/Main/area_id");
    for (auto it = domainMap.begin(); it != domainMap.end(); ++it)
    {
        m_mapAreaID[it->first] = S2I(it->second);
    }
}

void OuterFactoryImp::printAreaID()
{
    ostringstream os;
    os << "area id: ";
    for(auto it = m_mapAreaID.begin(); it != m_mapAreaID.end(); ++it)
    {
        os << ", key: " << it->first << ", valud: " << it->second;
    }
    FDLOG_CONFIG_INFO << os.str() << endl;
}
////////////////////////////////////////////////////////////////////////////////
