#include "Processor.h"
#include "LoginServer.h"
#include "globe.h"
#include "LogComm.h"
#include "DataProxyProto.h"
#include "ServiceDefine.h"
#include "util/tc_hash_fun.h"
#include "LogDefine.h"
#include "uuid.h"
#include "CommonCode.pb.h"
#include <regex>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <regex.h>
#include <assert.h>
#include "pcre.h"
#include "UserInfo.pb.h"
#include "jwt-cpp/jwt.h"
#include "iostream"
#include "cppcodec/base64_url_unpadded.hpp"
#include "util/tc_md5.h"
#include "ServiceUtil.h"
#include "smtp-ssl.h"
#include "TimeUtil.h"
#include "tinyxml2.h"

#define MIN_USERNAME_LEN 1           //用户名长度
#define MIN_PASSWD_LEN 4             //密码长度
#define MAX_UID_NUMBER_PER_ACCOUNT 1 //每个账号对应一个uid
#define TOKEN_EXPTIME 3 * 30 * 24 * 3600
#define LOGIN_AUTH_EXPTIME 3* 24 * 3600

static const int AUTH_CODE_VALIDITY_PERIOD = 300; //验证码有效期

using namespace std;
using namespace dataproxy;
using namespace dbagent;
using namespace userinfo;

// extern tars::Int32 getAreaID(const string &addr);
// extern tars::Int32 getAreaID(const map<std::string, std::string> &extraInfo, AreaIDReq &req, AreadIDResp &rsp);

//拆分字符串
static vector<std::string> split(const string &str, const string &pattern)
{
    return TC_Common::sepstr<string>(str, pattern);
}

//格式化时间
static std::string CurTimeFormat()
{
    std::string sFormat("%Y%m%d%H%M%S");
    time_t t = TNOW;
    auto ptr = localtime(&t);
    if (!ptr)
        return string("");

    char buffer[255] = "\0";
    strftime(buffer, sizeof(buffer), sFormat.c_str(), ptr);
    return string(buffer);
}

/**
 * 检查手机号码有效性
 * @param  str [description]
 * @return     [description]
 */
static bool checkPhoneNumber(std::string str)
{
    if (str.empty())
        return false;

    int erroff;
    const char *error;
    // const char *pattern = "^1([3-9])\\d{9}$";
    const char *pattern = "^[0-9]*$";//纯数字
    pcre *ptr = pcre_compile(pattern, 0, &error, &erroff, NULL);
    if (!ptr)
    {
        ROLLLOG_ERROR << "Mobile phone number regular expression error" << endl;
        return false;
    }

    int offset[64];
    int ret = pcre_exec(ptr, NULL, str.c_str(), str.length(), 0, 0, offset, sizeof(offset));
    if (ret < 0)
    {
        ROLLLOG_ERROR << "Mobile phone number matching failed, ret=" << ret << endl;
        pcre_free(ptr);
        return false;
    }

    ROLLLOG_DEBUG << "Mobile phone number matched successfully" << endl;
    pcre_free(ptr);
    return true;
}

//替换指定字符串
static std::string replace( const std::string &inStr, const char *pSrc, const char *pReplace )
{
    std::string str = inStr;
    std::string::size_type stStart = 0;
    std::string::iterator iter = str.begin();
    while (iter != str.end())
    {
        // 从指定位置 查找下一个要替换的字符串的起始位置。
        std::string::size_type st = str.find( pSrc, stStart );
        if ( st == str.npos )
            break;

        iter = iter + st - stStart;
        // 将目标字符串全部替换。
        str.replace( iter, iter + strlen( pSrc ), pReplace );
        iter = iter + strlen( pReplace );
        // 替换的字符串下一个字符的位置
        stStart = st + strlen( pReplace );
    }

    return str;
}

Processor::Processor()
{

}

Processor::~Processor()
{

}

int Processor::updateUserLoginTime(long uid, const string name)
{
    userinfo::UpdateUserInfoReq updateUserInfoReq;
    updateUserInfoReq.uid = uid;

    updateUserInfoReq.updateInfo = {
        {name, g_app.getOuterFactoryPtr()->GetTimeFormat()},
    };

    //userinfo::UpdateUserInfoResp updateUserInfoResp;
    g_app.getOuterFactoryPtr()->getHallServantPrx(uid)->async_UpdateUserInfo(NULL, updateUserInfoReq);
   /* if (iRet != 0)
    {
        ROLLLOG_ERROR << "updateUserInfo failed, uid: " << uid << endl;
        return -1;
    }*/
    return 0;
}

//跟新账户
int Processor::updateUserAccountInfo(long uid, const string &sRemoteIp, const string& deviceid, int flag, const int iPlatform, const int iSysVersion)
{
    LOG_DEBUG << "sRemoteIp: "<< sRemoteIp<< ", deviceid: "<< deviceid << endl;
    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(uid);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    userinfo::UpdateUserAccountReq updateUserAccountReq;
    updateUserAccountReq.uid = uid;

    if(!sRemoteIp.empty())
    {
        string country_id = getCountryByIP(sRemoteIp);
        updateUserAccountReq.updateInfo.insert(std::make_pair("country_id", country_id));
    }

    if(flag == 1)//登录
    {
        updateUserAccountReq.updateInfo.insert(std::make_pair("device_id", deviceid));

        userinfo::UpdateUserInfoReq updateUserInfoReq;
        updateUserInfoReq.uid = uid;
        updateUserInfoReq.updateInfo.insert(std::make_pair("last_login_ip", sRemoteIp));
        if (iPlatform != 0)
        {
            updateUserInfoReq.updateInfo.insert(std::make_pair("platform", I2S(iPlatform)));
            updateUserInfoReq.updateInfo.insert(std::make_pair("sys_version", I2S(iSysVersion)));
        }
        g_app.getOuterFactoryPtr()->getHallServantPrx(uid)->async_UpdateUserInfo(NULL, updateUserInfoReq);
    }
    else//注册
    {
        updateUserAccountReq.updateInfo.insert(std::make_pair("reg_device_no", deviceid));
        updateUserAccountReq.updateInfo.insert(std::make_pair("reg_ip", sRemoteIp));
    }

    if(updateUserAccountReq.updateInfo.size() > 0)
    {
        g_app.getOuterFactoryPtr()->getHallServantPrx(uid)->async_updateUserAccount(NULL, updateUserAccountReq);
    }

    return 0;
}

int Processor::checkWhiteList(const long lPlayerID)
{
    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(lPlayerID);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null, lPlayerID: " << lPlayerID << endl;
        return XGameRetCode::LOGIN_USER_SERVER_UPDATE;
    }

    //查询维护时间
    int keyIndex = 10000;

    dataproxy::TReadDataReq dataReq;
    dataReq.resetDefautlt();
    dataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(SERVER_UPDATE) + ":" + L2S(keyIndex);
    dataReq.operateType = E_REDIS_READ;
    dataReq.clusterInfo.resetDefautlt();
    dataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
    dataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
    dataReq.clusterInfo.frageFactor = keyIndex;

    vector<TField> fields;
    TField tfield;
    tfield.colArithType = E_NONE;
    tfield.colName = "begin_time";
    tfield.colType = BIGINT;
    fields.push_back(tfield);
    tfield.colName = "end_time";
    tfield.colType = BIGINT;
    fields.push_back(tfield);
    dataReq.fields = fields;

    TReadDataRsp dataRsp;
    int iRet = pDBAgentServant->redisRead(dataReq, dataRsp);
    ROLLLOG_DEBUG << "get server update, iRet: " << iRet << ", dataRsp: " << printTars(dataRsp) << endl;
    if (iRet != 0 || dataRsp.iResult != 0)
    {
        ROLLLOG_ERROR << "get server update, iRet: " << iRet << ", iResult: " << dataRsp.iResult << endl;
        return XGameRetCode::LOGIN_USER_SERVER_UPDATE;
    }

    long beginTime = 0;
    long endTime = 0;
    for (auto it = dataRsp.fields.begin(); it != dataRsp.fields.end(); ++it)
    {
        for (auto ituid = it->begin(); ituid != it->end(); ++ituid)
        {
            if (ituid->colName == "begin_time")
            {
                beginTime = S2L(ituid->colValue);
            }
            else if (ituid->colName == "end_time")
            {
                endTime = S2L(ituid->colValue);
            }
        }
    }

    LOG_DEBUG << "beginTime:"<< beginTime << ", endTime:"<< endTime << ", nowTime:"<< TNOW << endl;
    if(TNOW > beginTime && TNOW < endTime)
    {
        if(lPlayerID == 0)
        {
            return XGameRetCode::LOGIN_USER_SERVER_UPDATE;
        }
        userinfo::GetUserAccountReq userAccountReq;
        userAccountReq.uid = lPlayerID;
        userinfo::GetUserAccountResp userAccountResp;
        iRet = g_app.getOuterFactoryPtr()->getHallServantPrx(lPlayerID)->getUserAccount(userAccountReq, userAccountResp);
        if (iRet != 0)
        {
            ROLLLOG_ERROR << "getUserAccount failed, lPlayerID: " << lPlayerID << endl;
            return XGameRetCode::LOGIN_USER_SERVER_UPDATE;
        }

        return userAccountResp.useraccount.isinwhitelist == 1 ? 0 : XGameRetCode::LOGIN_USER_SERVER_UPDATE;
    }

    return 0;
}

//登出
int Processor::UserLogout(const LoginProto::LogoutReq &req, LoginProto::LogoutResp &rsp, bool sysOp, string ip)
{
    if (req.uid() < 0)
    {
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.uid());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null" << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //读取token
    string exptime = "";

    //获取登录密钥
    if (true)
    {
        dataproxy::TReadDataReq dataReq;
        dataReq.resetDefautlt();
        dataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(req.uid());
        dataReq.operateType = E_REDIS_READ;
        dataReq.clusterInfo.resetDefautlt();
        dataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
        dataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
        dataReq.clusterInfo.frageFactor = req.uid();

        vector<TField> fields;
        TField tfield;
        tfield.colArithType = E_NONE;
        tfield.colName = "uid";
        fields.push_back(tfield);
        tfield.colName = "exptime";
        fields.push_back(tfield);
        dataReq.fields = fields;

        TReadDataRsp dataRsp;
        int iRet = pDBAgentServant->redisRead(dataReq, dataRsp);
        ROLLLOG_DEBUG << "read user token data, iRet: " << iRet << ", datareq: " << printTars(dataReq) << ", dataRsp: " << printTars(dataRsp) << endl;
        if (iRet != 0 || dataRsp.iResult != 0)
        {
            ROLLLOG_ERROR << "read user token err, iRet: " << iRet << ", iResult: " << dataRsp.iResult << endl;
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        for (auto it = dataRsp.fields.begin(); it != dataRsp.fields.end(); ++it)
        {
            for (auto itfields = it->begin(); itfields != it->end(); ++itfields)
            {
                if (itfields->colName == "exptime")
                {
                    exptime = itfields->colValue;
                    break;
                }
            }
        }
    }

    userinfo::GetUserAccountResp userAccountResp;
    //更新帐户资料
    if (true)
    {
        userinfo::GetUserAccountReq userAccountReq;
        userAccountReq.uid = req.uid();
        int iRet = g_app.getOuterFactoryPtr()->getHallServantPrx(userAccountReq.uid)->getUserAccount(userAccountReq, userAccountResp);
        if (iRet != 0)
        {
            ROLLLOG_ERROR << "getUserAccount failed, uid: " << userAccountReq.uid << endl;
            return -1;
        }
    }

    //删除token
    if (true)
    {
        dataproxy::TWriteDataRsp dataRsp;
        dataproxy::TWriteDataReq dataReq;
        dataReq.resetDefautlt();
        dataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(req.uid());
        dataReq.operateType = E_REDIS_DELETE;
        dataReq.clusterInfo.resetDefautlt();
        dataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
        dataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
        dataReq.clusterInfo.frageFactor = req.uid();
        int iRet = pDBAgentServant->redisWrite(dataReq, dataRsp);
        ROLLLOG_DEBUG << "delete user token data, iRet: " << iRet << ", datareq: " << printTars(dataReq) << ", dataRsp: " << printTars(dataRsp) << endl;
        if (iRet != 0 || dataRsp.iResult != 0)
        {
            ROLLLOG_ERROR << "delete user token err, iRet: " << iRet << ", iResult: " << dataRsp.iResult << endl;
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }
    }

    //用户登出日志
    if (true)
    {
        long loginTime = time(NULL) - (S2L(exptime) - TOKEN_EXPTIME);
        if (loginTime < 0)
        {
            loginTime = 0;
        }

        vector<string> vLogLogout;
        vLogLogout.push_back(I2S(APP_ID));
        vLogLogout.push_back("1001");
        vLogLogout.push_back(I2S(userAccountResp.useraccount.channnelID));
        vLogLogout.push_back(I2S(userAccountResp.useraccount.areaID));
        vLogLogout.push_back(I2S(userAccountResp.useraccount.platform));
        vLogLogout.push_back(L2S(req.uid()));
        vLogLogout.push_back(userAccountResp.useraccount.deviceID);
        vLogLogout.push_back(userAccountResp.useraccount.regIp);
        vLogLogout.push_back("2");
        vLogLogout.push_back(L2S(loginTime));
        g_app.getOuterFactoryPtr()->asyncLog2DB(req.uid(), 21, vLogLogout);
    }

    rsp.set_resultcode(0);

    updateUserLoginTime(req.uid(), "last_logout_time");

    return 0;
}

int Processor::QuickLogin(const LoginProto::QuickLoginReq &req, LoginProto::QuickLoginResp &rsp, const map<string, string> &extraInfo)
{
    LOG_DEBUG << "QuickLoginReq:"<< logPb(req)<< endl;

    int iRet = 0;
    if (req.token().length() <= 0 || req.uid() <= 0)
    {
        ROLLLOG_ERROR << "parameter empty, token : " << req.token() << ", uid:" << req.uid() << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.uid());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null" << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    iRet = checkWhiteList(req.uid());
    if(iRet != 0)
    {
        return iRet;
    }

    TReadDataReq dataReq;
    dataReq.resetDefautlt();
    dataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(req.uid());
    dataReq.operateType = E_REDIS_READ;
    dataReq.clusterInfo.resetDefautlt();
    dataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
    dataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
    dataReq.clusterInfo.frageFactor = req.uid();

    vector<TField> fields;

    TField tfield;
    tfield.colArithType = E_NONE;
    tfield.colName = "token";
    fields.push_back(tfield);
    tfield.colName = "exptime";
    fields.push_back(tfield);
    dataReq.fields = fields;

    dataproxy::TReadDataRsp dataRsp;
    iRet = pDBAgentServant->redisRead(dataReq, dataRsp);
    if (iRet != 0)
    {
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    std::string token;
    long exptime = 0;
    for (auto it = dataRsp.fields.begin(); it != dataRsp.fields.end(); ++it)
    {
        for (auto itfield = it->begin(); itfield != it->end(); ++itfield)
        {
            if (itfield->colName == "exptime")
            {
                exptime = S2L(itfield->colValue);
            }
            else if (itfield->colName == "token")
            {
                token = itfield->colValue;
            }
        }
    }

    if (token != req.token())
    {
        ROLLLOG_ERROR << "uid:" << req.uid() << "token not equal. in token: " << token << ", out token :" << req.token() << endl;
        return XGameRetCode::LOGIN_TOKEN_INCONSISTENT;
    }

    if (exptime < time(NULL))
    {
        ROLLLOG_ERROR << "token is expired. exptime " << exptime << ", now :" << time(NULL) << endl;
        return XGameRetCode::LOGIN_TOKEN_EXPIRED;
    }

    string strToken = generateUUIDStr();

    dataproxy::TWriteDataReq wdataReq;
    wdataReq.resetDefautlt();
    wdataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(req.uid());
    wdataReq.operateType = E_REDIS_WRITE;
    wdataReq.clusterInfo.resetDefautlt();
    wdataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
    wdataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
    wdataReq.clusterInfo.frageFactor = req.uid();

    fields.clear();
    tfield.colName = "token";
    tfield.colType = STRING;
    tfield.colValue = strToken;
    fields.push_back(tfield);
    tfield.colName = "exptime";
    tfield.colType = BIGINT;
    tfield.colValue = L2S(time(NULL) + TOKEN_EXPTIME);
    fields.push_back(tfield);
    wdataReq.fields = fields;

    TWriteDataRsp wdataRsp;
    iRet = pDBAgentServant->redisWrite(wdataReq, wdataRsp);
    ROLLLOG_DEBUG << "set token data, iRet: " << iRet << ", wdataRsp: " << printTars(wdataRsp) << endl;
    if (iRet != 0 || dataRsp.iResult != 0)
    {
        ROLLLOG_ERROR << "save token data err, iRet: " << iRet << ", iResult: " << dataRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    userinfo::GetUserBasicReq userBasicReq;
    userBasicReq.uid = req.uid();
    userinfo::GetUserBasicResp userBasicResp;
    iRet = g_app.getOuterFactoryPtr()->getHallServantPrx(userBasicReq.uid)->getUserBasic(userBasicReq, userBasicResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "getUserBasic failed, uid: " << userBasicReq.uid << endl;
        return -1;
    }

    userinfo::GetUserAccountReq userAccountReq;
    userAccountReq.uid = req.uid();
    userinfo::GetUserAccountResp userAccountResp;
    iRet = g_app.getOuterFactoryPtr()->getHallServantPrx(userAccountReq.uid)->getUserAccount(userAccountReq, userAccountResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "getUserAccount failed, uid: " << userAccountReq.uid << endl;
        return -2;
    }

    rsp.set_uid(req.uid());
    rsp.set_token(strToken);
    rsp.set_logintype(req.logintype());
    rsp.set_flag(0);
    rsp.set_need_safe_auth(false);
    rsp.set_bind_phone(userAccountResp.useraccount.bindPhone);
    rsp.set_bind_email(userAccountResp.useraccount.bindEmail);

    //需要验证
    if(req.logintype() == 1 && userBasicResp.userinfo.safe_auth == "1" && (!userAccountResp.useraccount.bindPhone.empty() || !userAccountResp.useraccount.bindEmail.empty()) &&
        (std::abs(userBasicResp.userinfo.lastLoginTime - TNOW) > LOGIN_AUTH_EXPTIME))
    {
        rsp.set_need_safe_auth(true);
    }

    LOG_DEBUG << "QuickLoginResp:"<< logPb(rsp)<< endl;

    //login addr
    string sRemoteIp = "";
    auto iter = extraInfo.find("RemoteIp");
    if (iter != extraInfo.end())
        sRemoteIp = (*iter).second;

    updateUserAccountInfo(req.uid(), sRemoteIp,  req.deviceid());
    return iRet;
}

//游客登录
int Processor::DeviceLogin(const LoginProto::DeviceLoginReq &req, LoginProto::DeviceLoginResp &rsp, const map<string, string> &extraInfo, const int iVer)
{
    if (req.deviceno().length() <= 0)
    {
        ROLLLOG_ERROR << "parameter empty, device num len: " << req.deviceno().length() << ", ret: -1" << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.deviceno());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null" << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    TGetRegisterInfoReq getRegisterReq;
    getRegisterReq.keyIndex = 0;
    getRegisterReq.tableName = "tb_useraccount";
    getRegisterReq.userName = req.deviceno();
    getRegisterReq.iThirdParty = 0;

    TGetRegisterInfoRsp getRegisterRsp;
    int iRet = pDBAgentServant->getRegisterInfo(getRegisterReq, getRegisterRsp);
    ROLLLOG_DEBUG << "DeviceLogin info, iRet: " << iRet << ", getRegisterRsp: " << printTars(getRegisterRsp) << endl;
    if ((iRet != 0) || (getRegisterRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "DeviceLogin info err, iRet: " << iRet << ", iResult: " << getRegisterRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //login token
    string strToken = generateUUIDStr();
    //login addr
    string sRemoteIp = "";
    auto iter = extraInfo.find("RemoteIp");
    if (iter != extraInfo.end())
        sRemoteIp = (*iter).second;

    long lUid = getRegisterRsp.lUid;

    iRet = checkWhiteList(lUid);
    if(iRet != 0)
    {
        return iRet;
    }

    vector<TField> fields;
    TField tfield;
    tfield.colArithType = E_NONE;
    if ( lUid > 0)
    {
        //生成登录密钥
        TWriteDataReq wdataReq2;
        TWriteDataRsp wdataRsp2;
        wdataReq2.resetDefautlt();
        wdataReq2.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(lUid);
        wdataReq2.operateType = E_REDIS_WRITE;
        wdataReq2.clusterInfo.resetDefautlt();
        wdataReq2.clusterInfo.busiType = E_REDIS_PROPERTY;
        wdataReq2.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
        wdataReq2.clusterInfo.frageFactor = lUid;

        fields.clear();
        tfield.colName = "token";
        tfield.colType = STRING;
        tfield.colValue = strToken;
        fields.push_back(tfield);
        tfield.colName = "exptime";
        tfield.colType = BIGINT;
        tfield.colValue = L2S(time(NULL) + TOKEN_EXPTIME);
        fields.push_back(tfield);
        wdataReq2.fields = fields;
        iRet = pDBAgentServant->redisWrite(wdataReq2, wdataRsp2);
        ROLLLOG_DEBUG << "set token data, iRet: " << iRet << ", wdataRsp2: " << printTars(wdataRsp2) << endl;
        if (iRet != 0 || wdataRsp2.iResult != 0)
        {
            ROLLLOG_ERROR << "save token data err, iRet: " << iRet << ", iResult: " << wdataRsp2.iResult << endl;
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        //用户登录日志
        vector<string> vLogLogin;
        vLogLogin.push_back(I2S(APP_ID));
        vLogLogin.push_back("1001");
        vLogLogin.push_back(I2S((int)req.channnelid()));
        vLogLogin.push_back(I2S(req.areaid()));
        vLogLogin.push_back(I2S((int)req.platform()));
        vLogLogin.push_back(L2S(lUid));
        vLogLogin.push_back(req.deviceid());
        vLogLogin.push_back(sRemoteIp);
        vLogLogin.push_back("1");
        vLogLogin.push_back("0");
        g_app.getOuterFactoryPtr()->asyncLog2DB(lUid, 21, vLogLogin);

    }
    else
    {
        //生成用户标识
        TGetTableGUIDRsp insertIDRsp;
        TGetTableGUIDReq insertIDReq;
        insertIDReq.keyIndex = 0;
        insertIDReq.tableName = "tb_uid_guid";
        insertIDReq.fieldName = "uid";
        iRet = pDBAgentServant->getTableGUID(insertIDReq, insertIDRsp);
        ROLLLOG_DEBUG << "get last insert id, iRet: " << iRet << ", insertIDRsp: " << printTars(insertIDRsp) << endl;
        if (insertIDRsp.iResult != 0)
        {
            ROLLLOG_ERROR << "fetch new user id err, iRet: " << iRet << ", iResult: " << insertIDRsp.iResult << endl;
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        lUid = insertIDRsp.lastID;

        //注册帐号
        userinfo::InitUserResp initUserResp;
        userinfo::InitUserReq initUserReq;
        initUserReq.uid = lUid;
        initUserReq.userName = req.deviceno();
        initUserReq.passwd = "123456";
        initUserReq.deviceID = req.deviceid();
        initUserReq.deviceType = req.devicetype();
        initUserReq.platform = (userinfo::E_Platform_Type)((int)req.platform());
        initUserReq.channnelID = (userinfo::E_Channel_ID)((int)req.channnelid());
        initUserReq.areaID = (req.areaid() <= 0) ? 86 : req.areaid();
        initUserReq.isRobot = 0;
        initUserReq.reg_type = E_Register_Type::E_REGISTER_TYPE_VISITOR;//游客
        initUserReq.language = req.language();
        initUserReq.country_id = getCountryByIP(sRemoteIp);

        auto pHallServant = g_app.getOuterFactoryPtr()->getHallServantPrx(lUid);
        if (!pHallServant)
        {
            ROLLLOG_ERROR << "pHallServant is null" << endl;
            return XGameRetCode::SYS_ERROR;
        }

        iRet = pHallServant->createUser(initUserReq, initUserResp);
        if (iRet != 0)
        {
            ROLLLOG_ERROR << "init user info err, iRet: " << iRet << endl;
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        // 绑定代理
        if (req.recommendid() > 0)
        {
            iRet = g_app.getOuterFactoryPtr()->getHallServantPrx(lUid)->addRecommend(lUid, req.recommendid());
            if (iRet != 0)
            {
                ROLLLOG_ERROR << "addRecommend error! uid:" << lUid << ", reconnendID:" << req.recommendid() << endl;
                iRet = 0;
            }
        }

        //注册日志
        vector<string> vLogRegister;
        vLogRegister.push_back(I2S(APP_ID));                   //AppId|DB_STR
        vLogRegister.push_back("1001");                        //GameId|DB_STR
        vLogRegister.push_back(I2S(initUserReq.channnelID));   //ChannelId|DB_STR
        vLogRegister.push_back("0");                           //AreaId|DB_STR
        vLogRegister.push_back(I2S(initUserReq.platform));     //Platform|DB_STR
        vLogRegister.push_back(L2S(lUid));          //Uuid|DB_STR
        vLogRegister.push_back(initUserReq.userName);          //UserAccount|DB_STR
        vLogRegister.push_back(initUserReq.deviceID);          //DeviceId|DB_STR
        vLogRegister.push_back(initUserReq.deviceType);        //DeviceType|DB_STR
        vLogRegister.push_back(sRemoteIp);                     //Ip|DB_STR
        g_app.getOuterFactoryPtr()->asyncLog2DB(lUid, 20, vLogRegister);

        //生成登录密钥
        TWriteDataReq wdataReq2;
        TWriteDataRsp wdataRsp2;
        wdataReq2.resetDefautlt();
        wdataReq2.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(lUid);
        wdataReq2.operateType = E_REDIS_WRITE;
        wdataReq2.clusterInfo.resetDefautlt();
        wdataReq2.clusterInfo.busiType = E_REDIS_PROPERTY;
        wdataReq2.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
        wdataReq2.clusterInfo.frageFactor = lUid;

        fields.clear();
        tfield.colName = "token";
        tfield.colType = STRING;
        tfield.colValue = strToken;
        fields.push_back(tfield);
        tfield.colName = "exptime";
        tfield.colType = BIGINT;
        tfield.colValue = L2S(time(NULL) + TOKEN_EXPTIME);
        fields.push_back(tfield);
        wdataReq2.fields = fields;
        iRet = pDBAgentServant->redisWrite(wdataReq2, wdataRsp2);
        ROLLLOG_DEBUG << "set token data, iRet: " << iRet << ", wdataRsp2: " << printTars(wdataRsp2) << endl;
        if (iRet != 0 || wdataRsp2.iResult != 0)
        {
            ROLLLOG_ERROR << "save token data err, iRet: " << iRet << ", iResult: " << wdataRsp2.iResult << endl;
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        //用户登录日志
        vector<string> vLogLogin;
        vLogLogin.push_back(I2S(APP_ID));
        vLogLogin.push_back("1001");
        vLogLogin.push_back(I2S((int)req.channnelid()));
        vLogLogin.push_back(I2S(req.areaid()));
        vLogLogin.push_back(I2S((int)req.platform()));
        vLogLogin.push_back(L2S(lUid));
        vLogLogin.push_back(req.deviceid());
        vLogLogin.push_back(sRemoteIp);
        vLogLogin.push_back("1");
        vLogLogin.push_back("0");
        g_app.getOuterFactoryPtr()->asyncLog2DB(lUid, 21, vLogLogin);
    }

    //登录反馈消息
    rsp.set_resultcode(0);
    rsp.set_uid(lUid);
    rsp.set_token(strToken);
    rsp.set_flag(1);

    userinfo::GetUserAccountReq userAccountReq;
    userAccountReq.uid = lUid ;
    userinfo::GetUserAccountResp userAccountResp;
    iRet = g_app.getOuterFactoryPtr()->getHallServantPrx(userAccountReq.uid)->getUserAccount(userAccountReq, userAccountResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "getUserAccount failed, uid: " << userAccountReq.uid << endl;
        return -1;
    }

    userinfo::GetUserBasicReq userBasicReq;
    userBasicReq.uid = lUid ;
    userinfo::GetUserBasicResp userBasicResp;
    iRet = g_app.getOuterFactoryPtr()->getHallServantPrx(userBasicReq.uid)->getUserBasic(userBasicReq, userBasicResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "getUserBasic failed, uid: " << userBasicReq.uid << endl;
        return -2;
    }

    rsp.set_need_safe_auth(false);
    rsp.set_channnelid(LoginProto::E_Channel_ID(userAccountResp.useraccount.regType));
    rsp.set_username(userAccountResp.useraccount.userName);
    rsp.set_bind_phone(userAccountResp.useraccount.bindPhone);
    rsp.set_bind_email(userAccountResp.useraccount.bindEmail);

    //需要验证
    if(userBasicResp.userinfo.safe_auth == "1" && (!userAccountResp.useraccount.bindPhone.empty() || !userAccountResp.useraccount.bindEmail.empty()) &&
        ( std::abs(userBasicResp.userinfo.lastLoginTime - TNOW) > LOGIN_AUTH_EXPTIME))
    {
        rsp.set_need_safe_auth(true);
    }

    LOG_DEBUG << "DeviceLogin success, uid: " << lUid << ", rsp: " << logPb(rsp) << endl;
    updateUserAccountInfo(lUid, sRemoteIp, req.deviceid(), 1, (int)req.platform(), iVer);
    return 0;
}

int Processor::DeviceUpgrade(const LoginProto::DeviceUpgradeReq &req, LoginProto::DeviceUpgradeResp &rsp, const map<string, string> &extraInfo)
{
    LOG_DEBUG << "req: "<< logPb(req) << endl;
    long lUid = getAccountUid(req.registerreq().deviceid());
    if(lUid <= 0)
    {
        LOG_ERROR<< "account not exist. deviceid:"<< req.registerreq().deviceid() << endl;
        return XGameRetCode::LOGIN_EMAIL_ACCOUNT_NOT_EXSIT;
    }

    int iRet = checkWhiteList(lUid);
    if(iRet != 0)
    {
        return iRet;
    }

    if(getAccountUid(req.registerreq().username()) > 0)
    {
        LOG_ERROR<< "account exist. username:"<< req.registerreq().username() << endl;
        return XGameRetCode::LOGIN_EMAIL_ACCOUNT_EXSITED;
    }

    std::string sCode;
    time_t time = 0;
    if (XGameRetCode::SUCCESS != getAuthData(req.registerreq().deviceid(), sCode, time))
    {
        ROLLLOG_ERROR << "getAuthData() fail, username: " << req.registerreq().deviceid() << endl;
        return XGameRetCode::USER_INFO_PHONE_AUTH_CODE_ERROR;
    }

    if (TNOW - time >= AUTH_CODE_VALIDITY_PERIOD)
    {
        delAuthData(req.registerreq().deviceid());
        ROLLLOG_ERROR << "auto code timer out: " << req.registerreq().deviceid() << " time:" << time << endl;
        return XGameRetCode::USER_INFO_PHONE_AUTH_CODE_OVERDUE;
    }

    if (sCode != req.msgcode())
    {
        ROLLLOG_ERROR << "Invalid verification code, reqCode=" << req.msgcode() << ", svrCode=" << sCode << endl;
        return XGameRetCode::USER_INFO_PHONE_AUTH_CODE_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(lUid);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    std::string sBindStr = req.registerreq().channnelid() == LoginProto::E_CHANNEL_ID_PHOME ? "bindPhone" : "bindEmail";

    userinfo::UpdateUserAccountReq updateUserAccountReq;
    updateUserAccountReq.uid = lUid;
    updateUserAccountReq.updateInfo.insert(std::make_pair("username", req.registerreq().username()));
    updateUserAccountReq.updateInfo.insert(std::make_pair("password", req.registerreq().passwd()));
    updateUserAccountReq.updateInfo.insert(std::make_pair("reg_type", I2S(req.registerreq().channnelid())));
    updateUserAccountReq.updateInfo.insert(std::make_pair(sBindStr, req.registerreq().username()));
    g_app.getOuterFactoryPtr()->getHallServantPrx(lUid)->async_updateUserAccount(NULL, updateUserAccountReq);

    userinfo::UpdateUserInfoReq updateUserInfoReq;
    updateUserInfoReq.uid = lUid;
    updateUserInfoReq.updateInfo.insert(std::make_pair("area_code", I2S(req.registerreq().areaid())));
    userinfo::UpdateUserInfoResp updateUserInfoResp;
    return g_app.getOuterFactoryPtr()->getHallServantPrx(updateUserInfoReq.uid)->UpdateUserInfo(updateUserInfoReq, updateUserInfoResp);

}

//账号注册处理
int Processor::UserRegister(const login::RegisterReq req, login::RegisterResp &rsp, int areaID, string ip)
{
    return 0;
}

//账号注册处理
int Processor::UserRegister2(const LoginProto::RegisterReq req, LoginProto::RegisterResp &rsp, const map<std::string, std::string> &extraInfo)
{
    // if (ServiceUtil::check_characters(req.nickname()))
    // {
    //     ROLLLOG_ERROR << "parameter len too short, req.nickname: " << req.nickname() << endl;
    //     return XGameRetCode::LOGIN_PARAM_ERROR;
    // }

    ROLLLOG_DEBUG << "nickname:" << req.nickname() << " gender:" << req.gender() << endl;

    if (req.username().length() < MIN_USERNAME_LEN || req.passwd().length() < MIN_PASSWD_LEN)
    {
        ROLLLOG_ERROR << "parameter len too short, username: " << req.username() << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    long lUid = getAccountUid(req.username());
    if (lUid > 0)
    {
        ROLLLOG_ERROR << "username exist, lUid: " << lUid << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    TGetTableGUIDReq insertIDReq;
    insertIDReq.keyIndex = 0;
    insertIDReq.tableName = "tb_uid_guid";
    insertIDReq.fieldName = "uid";

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.username());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    TGetTableGUIDRsp insertIDRsp;
    int iRet = pDBAgentServant->getTableGUID(insertIDReq, insertIDRsp);
    ROLLLOG_DEBUG << "get last insert id, iRet: " << iRet << ", insertIDRsp: " << printTars(insertIDRsp) << endl;
    if (insertIDRsp.iResult != 0)
    {
        ROLLLOG_ERROR << "fetch new user id err, iRet: " << iRet << ", iResult: " << insertIDRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //注册帐号
    InitUserReq initUserReq;
    initUserReq.uid = insertIDRsp.lastID;
    initUserReq.userName = req.username();
    initUserReq.passwd = req.passwd();
    initUserReq.deviceID = req.deviceid();
    initUserReq.deviceType = req.devicetype();
    initUserReq.areaID = (req.areaid() <= 0) ? 86 : req.areaid();
    initUserReq.isRobot = 0;
    initUserReq.reg_type = E_Register_Type::E_REGISTER_TYPE_VISITOR;
    initUserReq.nickName = req.nickname();
    initUserReq.gender = req.gender();
    initUserReq.language = req.language();

    switch (req.platform())
    {
    case E_Platform_Type::E_PLATFORM_TYPE_IOS:
        initUserReq.platform = E_PLATFORM_TYPE_IOS;
        break;
    case E_Platform_Type::E_PLATFORM_TYPE_ANDROID:
        initUserReq.platform = E_PLATFORM_TYPE_ANDROID;
        break;
    case E_Platform_Type::E_PLATFORM_TYPE_H5:
        initUserReq.platform = E_PLATFORM_TYPE_H5;
        break;
    default:
        initUserReq.platform = E_PLATFORM_TYPE_UNKNOWN;
        ROLLLOG_ERROR << "未知错误平台类型: " << req.platform() << endl;
        break;
    }

    switch (req.channnelid())
    {
    case E_Channel_ID::E_CHANNEL_ID_UNKNOWN:
        initUserReq.channnelID = E_CHANNEL_ID_UNKNOWN;
        break;
    case E_Channel_ID::E_CHANNEL_ID_TEST:
        initUserReq.channnelID = E_CHANNEL_ID_TEST;
        break;
    case E_Channel_ID::E_CHANNEL_ID_EMAIL:
        initUserReq.reg_type = E_Register_Type::E_REGISTER_TYPE_EMAIL;
        initUserReq.channnelID = E_CHANNEL_ID_EMAIL;
        break;
    case E_Channel_ID::E_CHANNEL_ID_PHOME:
        initUserReq.reg_type = E_Register_Type::E_REGISTER_TYPE_PHOME;
        initUserReq.channnelID = E_CHANNEL_ID_PHOME;
        break;
    default:
        ROLLLOG_ERROR << "未知错误渠道类型: " << req.channnelid() << endl;
        break;
    }

    //login addr
    string sRemoteIp = "";
    auto iter = extraInfo.find("RemoteIp");
    if (iter != extraInfo.end())
        sRemoteIp = (*iter).second;

    initUserReq.country_id = getCountryByIP(sRemoteIp);

    auto pHallServant = g_app.getOuterFactoryPtr()->getHallServantPrx(initUserReq.uid);
    if (!pHallServant)
    {
        ROLLLOG_ERROR << "pHallServant is null" << endl;
        return XGameRetCode::SYS_ERROR;
    }

    InitUserResp initUserResp;
    iRet = pHallServant->createUser(initUserReq, initUserResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "init user info err, iRet: " << iRet << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    updateUserAccountInfo(initUserReq.uid, sRemoteIp, req.deviceid(), 0);

    // 绑定代理
    if (req.recommendid() > 0)
    {
        iRet = g_app.getOuterFactoryPtr()->getHallServantPrx(initUserReq.uid)->addRecommend(initUserReq.uid, req.recommendid());
        if (iRet != 0)
        {
            ROLLLOG_ERROR << "addRecommend error! uid:" << initUserReq.uid << ", reconnendID:" << req.recommendid() << endl;
        }
    }

    //注册日志
    vector<string> vLogRegister;
    vLogRegister.push_back(I2S(APP_ID));              //AppId|DB_STR
    vLogRegister.push_back("1001");                   //GameId|DB_STR
    vLogRegister.push_back(I2S(req.channnelid()));    //ChannelId|DB_STR
    vLogRegister.push_back("0");                      //AreaId|DB_STR
    vLogRegister.push_back(I2S(req.platform()));      //Platform|DB_STR
    vLogRegister.push_back(L2S(insertIDRsp.lastID));  //Uuid|DB_STR
    vLogRegister.push_back(req.username());           //UserAccount|DB_STR
    vLogRegister.push_back(req.deviceid());           //DeviceId|DB_STR
    vLogRegister.push_back(req.devicetype());         //DeviceType|DB_STR
    vLogRegister.push_back(sRemoteIp);                //Ip|DB_STR
    g_app.getOuterFactoryPtr()->asyncLog2DB(insertIDRsp.lastID, 20, vLogRegister);

    rsp.set_resultcode(0);
    rsp.set_uid(insertIDRsp.lastID);
    return 0;
}

//手机号注册
int Processor::PhoneRegister(const LoginProto::PhoneRegisterReq &req, LoginProto::PhoneRegisterResp &rsp, const map<std::string, std::string> &extraInfo)
{

    int iRet = checkWhiteList(0);
    if(iRet != 0)
    {
        return iRet;
    }

    std::string sCode;
    time_t time = 0;
    if (XGameRetCode::SUCCESS != getAuthData(req.registerreq().username(), sCode, time))
    {
        ROLLLOG_ERROR << "getAuthData() fail, username: " << req.registerreq().username() << endl;
        return XGameRetCode::USER_INFO_PHONE_AUTH_CODE_ERROR;
    }

    if (TNOW - time >= AUTH_CODE_VALIDITY_PERIOD)
    {
        delAuthData(req.registerreq().username());
        ROLLLOG_ERROR << "auto code timer out: " << req.registerreq().username() << " time:" << time << endl;
        return XGameRetCode::USER_INFO_PHONE_AUTH_CODE_OVERDUE;
    }

    if (sCode != req.msgcode())
    {
        ROLLLOG_ERROR << "Invalid verification code, reqCode=" << req.msgcode() << ", svrCode=" << sCode << endl;
        return XGameRetCode::USER_INFO_PHONE_AUTH_CODE_ERROR;
    }    

    LoginProto::RegisterResp registerResp;
    iRet = UserRegister2(req.registerreq(), registerResp, extraInfo);
    if (iRet != XGameRetCode::SUCCESS)
    {
        ROLLLOG_ERROR << "username: " << req.registerreq().username() << " iRet:" << iRet << endl;
        if (iRet == XGameRetCode::LOGIN_SERVER_ERROR)
        {
            return XGameRetCode::USER_INFO_PHONE_ALREADY_USED;
        }
        return iRet;
    }

    delAuthData(req.registerreq().username());
    rsp.set_uid(registerResp.uid());
    return XGameRetCode::SUCCESS;
}

//账号登录处理
int Processor::UserLogin(const LoginProto::UserLoginReq &req, LoginProto::UserLoginResp &rsp, const map<string, string> &extraInfo, const int iVer)
{
    LOG_DEBUG << "req: "<< logPb(req)<< endl;
    if (req.username().length() < MIN_USERNAME_LEN || req.passwd().length() < MIN_PASSWD_LEN)
    {
        ROLLLOG_ERROR << "parameter len too short, username len: " << req.username() << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.username());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    //根据username查找uid
    TGetRegisterInfoReq getRegisterReq;
    getRegisterReq.keyIndex = 0;
    getRegisterReq.tableName = "tb_useraccount";
    getRegisterReq.userName = req.username();
    getRegisterReq.iThirdParty = 0;

    TGetRegisterInfoRsp getRegisterRsp;
    int iRet = pDBAgentServant->getRegisterInfo(getRegisterReq, getRegisterRsp);
    ROLLLOG_DEBUG << "get user register info, iRet: " << iRet << ", getRegisterRsp: " << printTars(getRegisterRsp) << endl;
    if ((iRet != 0) || (getRegisterRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "get user register info err, iRet: " << iRet << ", iResult: " << getRegisterRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //uid不合法
    if (getRegisterRsp.lUid <= 0)
    {
        ROLLLOG_ERROR << "getRegisterRsp.lUid err, lUid: " << getRegisterRsp.lUid << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    iRet = checkWhiteList(getRegisterRsp.lUid);
    if(iRet != 0)
    {
        return iRet;
    }

    userinfo::GetUserAccountReq userAccountReq;
    userAccountReq.uid = getRegisterRsp.lUid ;
    userinfo::GetUserAccountResp userAccountResp;
    iRet = g_app.getOuterFactoryPtr()->getHallServantPrx(userAccountReq.uid)->getUserAccount(userAccountReq, userAccountResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "getUserAccount failed, uid: " << userAccountReq.uid << endl;
        return -1;
    }

    //ROLLLOG_DEBUG << "userAccountResp: "<< printTars(userAccountResp)<< endl;

    if (req.passwd() != userAccountResp.useraccount.password)
    {
        ROLLLOG_ERROR << "password error, iRet: " << iRet << endl;
        return XGameRetCode::LOGIN_PASSWD_ERROR;
    }

    userinfo::GetUserBasicReq userBasicReq;
    userBasicReq.uid = getRegisterRsp.lUid ;
    userinfo::GetUserBasicResp userBasicResp;
    iRet = g_app.getOuterFactoryPtr()->getHallServantPrx(userAccountReq.uid)->getUserBasic(userBasicReq, userBasicResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "getUserBasic failed, uid: " << userAccountReq.uid << endl;
        return -2;
    }

    //生成token,并保存
    string strToken = generateUUIDStr();

    dataproxy::TWriteDataReq wdataReq;
    wdataReq.resetDefautlt();
    wdataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(getRegisterRsp.lUid);
    wdataReq.operateType = E_REDIS_WRITE;
    wdataReq.clusterInfo.resetDefautlt();
    wdataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
    wdataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
    wdataReq.clusterInfo.frageFactor = getRegisterRsp.lUid;

    vector<TField> fields;
    TField tfield;
    tfield.colArithType = E_NONE;
    tfield.colName = "token";
    tfield.colType = STRING;
    tfield.colValue = strToken;
    fields.push_back(tfield);
    tfield.colName = "exptime";
    tfield.colType = BIGINT;
    tfield.colValue = L2S(time(NULL) + TOKEN_EXPTIME);
    fields.push_back(tfield);
    wdataReq.fields = fields;

    TWriteDataRsp wdataRsp;
    iRet = pDBAgentServant->redisWrite(wdataReq, wdataRsp);
    ROLLLOG_DEBUG << "set token data, iRet: " << iRet << ", wdataRsp: " << printTars(wdataRsp) << endl;
    if (iRet != 0 || wdataRsp.iResult != 0)
    {
        ROLLLOG_ERROR << "save token data err, iRet: " << iRet << ", iResult: " << wdataRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    rsp.set_resultcode(0);
    rsp.set_uid(getRegisterRsp.lUid);
    rsp.set_token(strToken);
    rsp.set_need_safe_auth(false);
    rsp.set_bind_phone(userAccountResp.useraccount.bindPhone);
    rsp.set_bind_email(userAccountResp.useraccount.bindEmail);

    //需要验证
    if(userBasicResp.userinfo.safe_auth == "1" && (!userAccountResp.useraccount.bindPhone.empty() || !userAccountResp.useraccount.bindEmail.empty()) &&
        (std::abs(userBasicResp.userinfo.lastLoginTime - TNOW) > LOGIN_AUTH_EXPTIME))
    {
        rsp.set_need_safe_auth(true);
    }

    //login addr
    string sRemoteIp = "";
    auto iter = extraInfo.find("RemoteIp");
    if (iter != extraInfo.end())
        sRemoteIp = (*iter).second;

    //登录日志
    vector<string> vLogLogin;
    vLogLogin.push_back(I2S(APP_ID));              //AppId|DB_STR
    vLogLogin.push_back("1001");                   //GameId|DB_STR
    vLogLogin.push_back("0");                      //ChannelId|DB_STR
    vLogLogin.push_back("0");                      //AreaId|DB_STR
    vLogLogin.push_back("0");                      //Platform|DB_STR
    vLogLogin.push_back(L2S(getRegisterRsp.lUid)); //Uuid|DB_STR
    vLogLogin.push_back("");                       //DeviceId|DB_STR
    vLogLogin.push_back(sRemoteIp);                //Ip|DB_STR
    vLogLogin.push_back("1");                      //OperationCode|DB_STR
    vLogLogin.push_back("0");                      //OnlineTime|DB_STR
    g_app.getOuterFactoryPtr()->asyncLog2DB(getRegisterRsp.lUid, 21, vLogLogin);

    updateUserAccountInfo(getRegisterRsp.lUid, sRemoteIp, req.deviceid(), 1, (int)req.platform(), iVer);
    return 0;
}

//手机号码登录
int Processor::PhoneLogin(const LoginProto::PhoneLoginReq &req, LoginProto::PhoneLoginResp &rsp, const map<string, string> &extraInfo, const int iVer)
{
    auto &sc = g_app.getOuterFactoryPtr()->getSMSConfig();
    if (sc.isOpen)
    {
        if (req.channnelid() == LoginProto::E_CHANNEL_ID_TEST)
        {
            return TestLogin(req, rsp, extraInfo);
        }
    }

    if (!checkPhoneNumber(req.phone()))
    {
        ROLLLOG_ERROR << "checkPhoneNumber() fail, phone=" << req.phone() << endl;
        return XGameRetCode::USER_INFO_PHONE_FORMAT_ERROR;
    }

    int errCount = 0;
    time_t time = 0;
    int iRet = getPasswordErrCount(req.phone(), errCount, time);
    if (iRet == 0 && errCount >= 5 && (TNOW - time) < 7200)
    {
        ROLLLOG_ERROR << "account lockout, username: " << req.phone() << endl;
        return XGameRetCode::USER_INFO_PHONE_PASSWD_ERROR_LIMIT;
    }

    if (!ServiceUtil::check_password2(req.passwd(), req.passwd().size()))
    {
        rsp.set_passwderrcount(errCount + 1);
        addPasswordErrCount(req.phone());
        ROLLLOG_ERROR << "password err, username: " << logPb(req) << endl;
        return XGameRetCode::LOGIN_PASSWD_ERROR;
    }

    LoginProto::UserLoginReq userLoginReq;
    LoginProto::UserLoginResp userLoginResp;
    userLoginReq.set_username(req.phone());
    userLoginReq.set_passwd(req.passwd());
    userLoginReq.set_deviceid(req.deviceid());
    iRet = UserLogin(userLoginReq, userLoginResp, extraInfo, iVer);
    if (iRet != XGameRetCode::SUCCESS)
    {
        ROLLLOG_ERROR << "username: " << req.phone() << " errCount:" << errCount << " time:" << time << " iRet:" << iRet << endl;
        if (iRet == XGameRetCode::LOGIN_PASSWD_ERROR)
        {
            rsp.set_passwderrcount(errCount + 1);
            addPasswordErrCount(req.phone());
            ROLLLOG_ERROR << "password err, username: " << req.phone() << endl;
        }
        if (iRet == XGameRetCode::LOGIN_SERVER_ERROR)
        {
            return XGameRetCode::USER_INFO_PHONE_ACCOUNT_NOT_EXSIT;
        }
        return iRet;
    }

    rsp.set_uid(userLoginResp.uid());
    rsp.set_token(userLoginResp.token());
    rsp.set_need_safe_auth(userLoginResp.need_safe_auth());
    rsp.set_bind_phone(userLoginResp.bind_phone());
    rsp.set_bind_email(userLoginResp.bind_email());

    delPasswordErrCount(req.phone());
    return XGameRetCode::SUCCESS;
}

int Processor::TestLogin(const LoginProto::PhoneLoginReq &req, LoginProto::PhoneLoginResp &rsp, const map<string, string> &extraInfo)
{

    if ((req.phone().length() < MIN_USERNAME_LEN)/* || (req.areaid() <= 0)*/)
    {
        ROLLLOG_ERROR << "invalid phone, phone: " << req.phone()/* << " or areaID: " << req.areaid()*/ << endl;
        rsp.set_resultcode(-1001);
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.phone());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        rsp.set_resultcode(-1);
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    if (!checkPhoneNumber(req.phone()))
    {
        ROLLLOG_ERROR << "checkPhoneNumber() fail, phone=" << req.phone() << endl;
        rsp.set_resultcode(-1022);
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    //根据username查找uid
    TGetRegisterInfoReq getRegisterReq;
    getRegisterReq.keyIndex = 0;
    getRegisterReq.tableName = "tb_useraccount";
    getRegisterReq.userName = req.phone();
    getRegisterReq.iThirdParty = 0;

    TGetRegisterInfoRsp getRegisterRsp;
    int iRet = pDBAgentServant->getRegisterInfo(getRegisterReq, getRegisterRsp);
    ROLLLOG_DEBUG << "get user register info, iRet: " << iRet << ", getRegisterRsp: " << printTars(getRegisterRsp) << endl;
    if ((iRet != 0) || (getRegisterRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "get user register info err, iRet: " << iRet << ", iResult: " << getRegisterRsp.iResult << endl;
        rsp.set_resultcode(-1003);
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //获取用户标识
    tars::Int64 uid = getRegisterRsp.lUid;
    iRet = checkWhiteList(uid);
    if(iRet != 0)
    {
        return iRet;
    }

    if (uid <= 0)
    {
        LoginProto::RegisterReq regReq;
        regReq.set_username(req.phone());
        regReq.set_passwd(req.phone());
        regReq.set_deviceid(req.deviceid());
        regReq.set_devicetype(req.devicetype());
        regReq.set_platform(req.platform());
        regReq.set_channnelid(req.channnelid());
        regReq.set_nickname(req.nickname());
        regReq.set_gender(req.gender());

        LoginProto::RegisterResp regRsp;
        iRet = UserRegister2(regReq, regRsp, extraInfo);
        if (iRet != 0 && regRsp.resultcode() != 0)
        {
            ROLLLOG_ERROR << "username not exist, iRet: " << iRet << ", resultcode: " << regRsp.resultcode() << endl;
            rsp.set_resultcode(-1014);
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        uid = regRsp.uid();
    }

    //uid不合法
    if (uid <= 0)
    {
        ROLLLOG_ERROR << "uid err, uid: " << uid << endl;
        rsp.set_resultcode(-1005);
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    userinfo::GetUserAccountReq userAccountReq;
    userAccountReq.uid = uid;
    userinfo::GetUserAccountResp userAccountResp;
    iRet = g_app.getOuterFactoryPtr()->getHallServantPrx(uid)->getUserAccount(userAccountReq, userAccountResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "getUserAccount failed, uid: " << uid << endl;
        return -1;
    }

    string strToken = generateUUIDStr();

    dataproxy::TWriteDataReq wdataReq;
    wdataReq.resetDefautlt();
    wdataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(uid);
    wdataReq.operateType = E_REDIS_WRITE;
    wdataReq.clusterInfo.resetDefautlt();
    wdataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
    wdataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
    wdataReq.clusterInfo.frageFactor = uid;

    vector<TField> fields;
    TField tField;
    tField.colArithType = E_NONE;
    tField.colName = "token";
    tField.colType = STRING;
    tField.colValue = strToken;
    fields.push_back(tField);
    tField.colName = "exptime";
    tField.colType = BIGINT;
    tField.colValue = L2S(time(NULL) + TOKEN_EXPTIME);
    fields.push_back(tField);
    wdataReq.fields = fields;

    TWriteDataRsp wdataRsp;
    iRet = pDBAgentServant->redisWrite(wdataReq, wdataRsp);
    if (iRet != 0 || wdataRsp.iResult != 0)
    {
        ROLLLOG_ERROR << "save token data err, iRet: " << iRet << ", iResult: " << wdataRsp.iResult << endl;
        rsp.set_resultcode(-1010);
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //login addr
    string sRemoteIp = "";
    auto iter = extraInfo.find("RemoteIp");
    if (iter != extraInfo.end())
        sRemoteIp = (*iter).second;

    //登录日志
    vector<string> vLogLogin;
    vLogLogin.push_back(I2S(APP_ID));           //AppId|DB_STR
    vLogLogin.push_back("1001");                //GameId|DB_STR
    vLogLogin.push_back(I2S(req.channnelid())); //ChannelId|DB_STR
    vLogLogin.push_back("0");                   //AreaId|DB_STR
    vLogLogin.push_back(I2S(req.platform()));   //Platform|DB_STR
    vLogLogin.push_back(L2S(uid));              //Uuid|DB_STR
    vLogLogin.push_back(req.deviceid());        //DeviceId|DB_STR
    vLogLogin.push_back(sRemoteIp);             //Ip|DB_STR
    vLogLogin.push_back("1");                   //OperationCode|DB_STR
    vLogLogin.push_back("0");                   //OnlineTime|DB_STR
    g_app.getOuterFactoryPtr()->asyncLog2DB(uid, 21, vLogLogin);

    //登录消息应答
    rsp.set_resultcode(0);
    rsp.set_uid(uid);
    rsp.set_token(strToken);
    ROLLLOG_DEBUG << "set token data, iRet: " << iRet << ", wdataRsp: " << printTars(wdataRsp) << endl;

    return 0;
}

int Processor::PhoneResetPassword(const LoginProto::PhoneModifyPasswordReq &req, LoginProto::PhoneModifyPasswordResp &rsp)
{
    std::string sCode;
    time_t time = 0;
    if (XGameRetCode::SUCCESS != getAuthData(req.username(), sCode, time))
    {
        ROLLLOG_ERROR << "getAuthData() fail, strGetAuthPhone: " << req.username() << endl;
        return XGameRetCode::USER_INFO_PHONE_AUTH_CODE_ERROR;
    }

    if (TNOW - time >= AUTH_CODE_VALIDITY_PERIOD)
    {
        delAuthData(req.username());
        ROLLLOG_ERROR << "auto code timer out: " << req.username() << " time:" << time << endl;
        return XGameRetCode::USER_INFO_PHONE_AUTH_CODE_OVERDUE;
    }

    if (sCode != req.msgcode())
    {
        ROLLLOG_ERROR << "Invalid verification code, reqCode=" << req.msgcode() << ", svrCode=" << sCode << endl;
        return XGameRetCode::USER_INFO_PHONE_AUTH_CODE_ERROR;
    }

    delAuthData(req.username());
    delPasswordErrCount(req.username());

    return setUserPassword(req.username(), req.newpassword());
}

//发送手机验证码
int Processor::PhoneMsgCode(const LoginProto::SendPhoneMessageCodeReq &req, LoginProto::SendPhoneMessageCodeResp &rsp)
{
    int iRet = 0;

    LOG_DEBUG << "req: " << logPb(req)<< endl;

    if (req.phone().length() < MIN_USERNAME_LEN)
    {
        rsp.set_resultcode(XGameRetCode::LOGIN_PARAM_ERROR);
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    vector<string> details = split(req.phone(), "-");
    if ((int)details.size() != 2)
    {
        ROLLLOG_ERROR << "param error, req:" << logPb(req) << endl;
        rsp.set_resultcode(XGameRetCode::LOGIN_PARAM_ERROR);
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    string strArea = details[0];
    if (!checkPhoneNumber(strArea))
    {
        ROLLLOG_ERROR << "req:" << logPb(req) << endl;
        return XGameRetCode::ARG_INVALIDATE_ERROR;
    }

    string strPhone = details[1];
    if (!checkPhoneNumber(strPhone))
    {
        ROLLLOG_ERROR << "checkPhoneNumber() fail, req:" << logPb(req) << endl;
        rsp.set_resultcode(XGameRetCode::LOGIN_PARAM_ERROR);
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    string username;
    if(req.type() == 1)//注册发送验证码
    {
        iRet = checkWhiteList(0);
        if(iRet != 0)
        {
            return iRet;
        }
        if(getAccountUid(strPhone) > 0)
        {
            return XGameRetCode::USER_INFO_PHONE_ALREADY_USED;
        }
        username = strPhone;
    }
    else if(req.type() == 2)//重置密码
    {
        if(getAccountUid(strPhone) <= 0)
        {
            return XGameRetCode::USER_INFO_PHONE_ACCOUNT_NOT_EXSIT;
        }
        username = strPhone;
    }
    else
    {
        if(getAccountUid(req.username()) <= 0)
        {
            return XGameRetCode::USER_INFO_PHONE_ACCOUNT_NOT_EXSIT;
        }
        username = req.username();
    }

    std::string sCode;
    time_t time = 0;
    tars::Int32 iRandNum = ServiceUtil::rand_number(1000, 9999);
    iRet = getAuthData(strPhone, sCode, time);
    if (iRet == 0 && TNOW - time < AUTH_CODE_VALIDITY_PERIOD)
    {
        iRandNum = S2I(sCode);
    } 

    iRet = sendAuthCode(req.phone(), iRandNum);
    if (XGameRetCode::SUCCESS != iRet)
    {
        ROLLLOG_ERROR << "Send verification code fail: phone=" << req.phone() << ", code= " << iRandNum << ", iRet= " << iRet << endl;
        rsp.set_resultcode(XGameRetCode::USER_INFO_PHOME_SERVICE_UNAVAILABLE);
        return XGameRetCode::USER_INFO_PHOME_SERVICE_UNAVAILABLE;
    }

    if (XGameRetCode::SUCCESS != setAuthData(username, std::to_string(iRandNum)))
    {
        ROLLLOG_ERROR << "save verification code fail: username=" << req.username() << ", code= " << iRandNum << endl;
        rsp.set_resultcode(XGameRetCode::LOGIN_SERVER_ERROR);
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    ROLLLOG_DEBUG << "Send verification code succ: phone=" << req.phone() << ", code= " << iRandNum << endl;

    rsp.set_resultcode(XGameRetCode::SUCCESS);
    return XGameRetCode::SUCCESS;
}

//邮箱注册
int Processor::EmailRegister(const LoginProto::EmailRegisterReq &req, LoginProto::EmailRegisterResp &rsp, const map<std::string, std::string> &extraInfo)
{

    int iRet = checkWhiteList(0);
    if(iRet != 0)
    {
        return iRet;
    }

    std::string sCode;
    time_t time = 0;
    if (XGameRetCode::SUCCESS != getAuthData(req.registerreq().username(), sCode, time))
    {
        ROLLLOG_ERROR << "getAuthData() fail, strGetAuthEmail: " << req.registerreq().username() << endl;
        return XGameRetCode::LOGIN_EMAIL_AUTH_CODE_ERROR;
    }

    if (TNOW - time >= AUTH_CODE_VALIDITY_PERIOD)
    {
        delAuthData(req.registerreq().username());
        ROLLLOG_ERROR << "auto code timer out: " << req.registerreq().username() << " time:" << time << endl;
        return XGameRetCode::LOGIN_EMAIL_AUTH_CODE_TIMEROUT;
    }

    if (sCode != req.msgcode())
    {
        ROLLLOG_ERROR << "Invalid verification code, reqCode=" << req.msgcode() << ", svrCode=" << sCode << endl;
        return XGameRetCode::LOGIN_EMAIL_AUTH_CODE_ERROR;
    }    

    LoginProto::RegisterResp registerResp;
    iRet = UserRegister2(req.registerreq(), registerResp, extraInfo);
    if (iRet != XGameRetCode::SUCCESS)
    {
        ROLLLOG_ERROR << "username: " << req.registerreq().username() << " iRet:" << iRet << endl;
        if (iRet == XGameRetCode::LOGIN_SERVER_ERROR)
        {
            return XGameRetCode::LOGIN_EMAIL_ACCOUNT_EXSITED;
        }
        return iRet;
    }

    delAuthData(req.registerreq().username());
    rsp.set_uid(registerResp.uid());
    return XGameRetCode::SUCCESS;
}

//邮箱登录
int Processor::EmailLogin(const LoginProto::UserLoginReq &req, LoginProto::UserLoginResp &rsp, const map<string, string> &extraInfo, const int iVer)
{
    if (!ServiceUtil::check_email(req.username()))
    {
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    int errCount = 0;
    time_t time = 0;
    int iRet = getPasswordErrCount(req.username(), errCount, time);
    if (iRet == 0 && errCount >= 5 && (TNOW - time) < 7200)
    {
        ROLLLOG_ERROR << "account lockout, username: " << req.username() << endl;
        return XGameRetCode::LOGIN_EMAIL_PASSWD_ERROR_LIMIT;
    }

    if (!ServiceUtil::check_password2(req.passwd(), req.passwd().size()))
    {
        rsp.set_passwderrcount(errCount + 1);
        addPasswordErrCount(req.username());
        ROLLLOG_ERROR << "password err, username: " << req.username() << endl;
        return XGameRetCode::LOGIN_PASSWD_ERROR;
    }

    iRet = UserLogin(req, rsp, extraInfo, iVer);
    if (iRet != XGameRetCode::SUCCESS)
    {
        ROLLLOG_ERROR << "username: " << req.username() << " errCount:" << errCount << " time:" << time << " iRet:" << iRet << endl;
        if (iRet == XGameRetCode::LOGIN_PASSWD_ERROR)
        {
            rsp.set_passwderrcount(errCount + 1);
            addPasswordErrCount(req.username());
            ROLLLOG_ERROR << "password err, username: " << req.username() << endl;
        }
        if (iRet == XGameRetCode::LOGIN_SERVER_ERROR)
        {
            return XGameRetCode::LOGIN_EMAIL_ACCOUNT_NOT_EXSIT;
        }
        return iRet;
    }

    delPasswordErrCount(req.username());
    return XGameRetCode::SUCCESS;
}

//邮箱账号重置密码
int Processor::EmailResetPassword(const LoginProto::EmailModifyPasswordReq &req, LoginProto::EmailModifyPasswordResp &rsp)
{
    ROLLLOG_DEBUG << "EmailResetPassword "<< endl;
    std::string sCode;
    time_t time = 0;
    if (XGameRetCode::SUCCESS != getAuthData(req.username(), sCode, time))
    {
        ROLLLOG_ERROR << "getAuthData() fail, strGetAuthPhone: " << req.username() << endl;
        return XGameRetCode::LOGIN_EMAIL_AUTH_CODE_ERROR;
    }

    if (TNOW - time >= AUTH_CODE_VALIDITY_PERIOD)
    {
        delAuthData(req.username());
        ROLLLOG_ERROR << "auto code timer out: " << req.username() << " time:" << time << endl;
        return XGameRetCode::LOGIN_EMAIL_AUTH_CODE_TIMEROUT;
    }

    if (sCode != req.msgcode())
    {
        ROLLLOG_ERROR << "Invalid verification code, reqCode=" << req.msgcode() << ", svrCode=" << sCode << endl;
        return XGameRetCode::LOGIN_EMAIL_AUTH_CODE_ERROR;
    }

    delAuthData(req.username());
    delPasswordErrCount(req.username());

    return setUserPassword(req.username(), req.newpassword());
}

long Processor::getAccountUid(const string username)
{
    LOG_DEBUG << "userName: "<< username << endl;
    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(username);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return -1;
    }
    //根据username查找uid
    TGetRegisterInfoReq getRegisterReq;
    getRegisterReq.keyIndex = 0;
    getRegisterReq.tableName = "tb_useraccount";
    getRegisterReq.userName = username;
    getRegisterReq.iThirdParty = 0;

    TGetRegisterInfoRsp getRegisterRsp;
    int iRet = pDBAgentServant->getRegisterInfo(getRegisterReq, getRegisterRsp);
    ROLLLOG_DEBUG << "get user register info, iRet: " << iRet << ", getRegisterRsp: " << printTars(getRegisterRsp) << endl;
    if ((iRet != 0) || (getRegisterRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "get user register info err, iRet: " << iRet << ", iResult: " << getRegisterRsp.iResult << endl;
        return -2;
    }
    return getRegisterRsp.lUid;
}

//发送邮箱验证码
int Processor::EmailMsgCode(const LoginProto::SendEmailMessageCodeReq &req, LoginProto::SendEmailMessageCodeResp &rsp)
{
    ROLLLOG_DEBUG << "req: "<< logPb(req) << endl;

    string username;
    if(req.type() == 1)//注册发送验证码
    {
        int iRet = checkWhiteList(0);
        if(iRet != 0)
        {
            return iRet;
        }
        if(getAccountUid(req.email()) > 0)
        {
            return XGameRetCode::USER_INFO_PHONE_ALREADY_USED;
        }
        username = req.email();
    }
    else if(req.type() == 2)//重置密码
    {
        if(getAccountUid(req.email()) <= 0)
        {
            return XGameRetCode::USER_INFO_PHONE_ACCOUNT_NOT_EXSIT;
        }
        username = req.email();
    }
    else
    {
        if(getAccountUid(req.username()) <= 0)
        {
            return XGameRetCode::USER_INFO_PHONE_ACCOUNT_NOT_EXSIT;
        }
        username = req.username();
    }

    if (!ServiceUtil::check_email(req.email()))
    {
        return XGameRetCode::LOGIN_EMAIL_EMAIL_FROMAT_EROOR;
    }

    auto &emailCfg = g_app.getOuterFactoryPtr()->getEmailConfig();

    std::string subject = emailCfg.subject;
    std::string strCode = I2S(ServiceUtil::rand_number(1000, 9999));
    std::string email_body = replace(emailCfg.content, "msg", strCode.c_str());

/*    std::thread thread_send_email([=]() {
        std::string to_email = req.email();
        CSendEmail email_sender(emailCfg.from_email, to_email, emailCfg.cc_mail, emailCfg.passwd, emailCfg.smtp_server);
        email_sender.SendMail(subject, email_body, EncryptionMethod::SMTPS_SSL);
    });
    thread_send_email.detach();*/

    auto sendMail = [=]() {
        std::string to_email = req.email();
        CSendEmail email_sender(emailCfg.from_email, to_email, emailCfg.cc_mail, emailCfg.passwd, emailCfg.smtp_server);
        return email_sender.SendMail(subject, email_body, EncryptionMethod::SMTPS_SSL);
    };

    std::future<int> bar = std::async(std::launch::async, sendMail);
    int result = bar.get();

    if(result != 0)
    {
        ROLLLOG_ERROR << "send mail first fail. username: "<< username << ", result: "<< result << endl;
        std::async(std::launch::async, sendMail);//失败之后再发一次
    }

    if (XGameRetCode::SUCCESS != setAuthData(username, strCode))
    {
        ROLLLOG_ERROR << "save verification code fail: username=" << req.username() << ", code= " << strCode << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    ROLLLOG_DEBUG << "Send verification code succ: email=" << req.email() << ", code= " << strCode << endl;

    return XGameRetCode::SUCCESS;
}

int Processor::VerifyAuthCode(const LoginProto::VerifyAuthCodeReq &req, LoginProto::VerifyAuthCodeResp &rsp)
{
    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.username());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    LOG_DEBUG << "req: "<< logPb(req) << endl;

    //根据username查找uid
    TGetRegisterInfoReq getRegisterReq;
    getRegisterReq.keyIndex = 0;
    getRegisterReq.tableName = "tb_useraccount";
    getRegisterReq.userName = req.username();
    getRegisterReq.iThirdParty = 0;

    TGetRegisterInfoRsp getRegisterRsp;
    int iRet = pDBAgentServant->getRegisterInfo(getRegisterReq, getRegisterRsp);
    ROLLLOG_DEBUG << "get user register info, iRet: " << iRet << ", getRegisterRsp: " << printTars(getRegisterRsp) << endl;
    if ((iRet != 0) || (getRegisterRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "get user register info err, iRet: " << iRet << ", iResult: " << getRegisterRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //uid不合法
    if (getRegisterRsp.lUid <= 0)
    {
        ROLLLOG_ERROR << "getRegisterRsp.lUid err, lUid: " << getRegisterRsp.lUid << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    userinfo::GetUserAccountReq userAccountReq;
    userAccountReq.uid = getRegisterRsp.lUid;
    userinfo::GetUserAccountResp userAccountResp;
    iRet = g_app.getOuterFactoryPtr()->getHallServantPrx(userAccountReq.uid)->getUserAccount(userAccountReq, userAccountResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "getUserAccount failed, uid: " << userAccountReq.uid << endl;
        return -1;
    }

    LOG_DEBUG << "userName: "<< userAccountResp.useraccount.userName << endl;
    time_t time;
    std::string authCode;
    iRet = getAuthData(userAccountResp.useraccount.userName, authCode, time);
    if (iRet != 0 || req.msgcode() != authCode)
    {
        ROLLLOG_ERROR << "getAuthData error: iRet:" << iRet << ", authCode:" << authCode << " code:" << req.msgcode() << endl;
        return XGameRetCode::USER_INFO_PHONE_AUTH_CODE_ERROR;
    }

    if ((TNOW - time) >= AUTH_CODE_VALIDITY_PERIOD)
    {
        ROLLLOG_ERROR << "authCode timeout:" << (TNOW - time) << " code:" << authCode << " code:" << req.msgcode() << endl;
        return XGameRetCode::USER_INFO_PHONE_AUTH_CODE_OVERDUE;
    }

    //删除验证码
    delAuthData(userAccountResp.useraccount.userName);

    return 0;
}

int Processor::RegisterUserInfo( const LoginProto::RegisterUserInfoReq &req)
{
    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.username());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    //根据username查找uid
    TGetRegisterInfoReq getRegisterReq;
    getRegisterReq.keyIndex = 0;
    getRegisterReq.tableName = "tb_useraccount";
    getRegisterReq.userName = req.username();
    getRegisterReq.iThirdParty = 0;

    TGetRegisterInfoRsp getRegisterRsp;
    int iRet = pDBAgentServant->getRegisterInfo(getRegisterReq, getRegisterRsp);
    ROLLLOG_DEBUG << "get user register info, iRet: " << iRet << ", getRegisterRsp: " << printTars(getRegisterRsp) << endl;
    if ((iRet != 0) || (getRegisterRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "get user register info err, iRet: " << iRet << ", iResult: " << getRegisterRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //uid不合法
    if (getRegisterRsp.lUid <= 0)
    {
        ROLLLOG_ERROR << "getRegisterRsp.lUid err, lUid: " << getRegisterRsp.lUid << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    userinfo::UpdateUserInfoReq updateUserInfoReq;
    updateUserInfoReq.uid = getRegisterRsp.lUid;

    LOG_DEBUG << "req: "<< logPb(req)<< endl;
    if(!req.head().empty())
    {
        updateUserInfoReq.updateInfo.insert(std::make_pair("head_str", req.head()));
    }
    if(!req.nickname().empty())
    {
        updateUserInfoReq.updateInfo.insert(std::make_pair("nickname", req.nickname()));
    }
    updateUserInfoReq.updateInfo.insert(std::make_pair("gender", I2S(req.gender())));

    userinfo::UpdateUserInfoResp updateUserInfoResp;
    return g_app.getOuterFactoryPtr()->getHallServantPrx(getRegisterRsp.lUid)->UpdateUserInfo(updateUserInfoReq, updateUserInfoResp);
}


static bool queryRounterForConfigServer(config::ListRounterCfgResp &rsp)
{
    auto pConfigServant = g_app.getOuterFactoryPtr()->getConfigServantPrx();
    if (!pConfigServant)
    {
        ROLLLOG_ERROR << "load rounter info failed: pConfigServant is null" << endl;
        return false;
    }

    // //每分钟更新一次路由信息
    // static config::ListRounterCfgResp temp;
    // static std::atomic<int> lastUpdateTime(0);
    // if (TNOW - lastUpdateTime > 60)
    // {
    //     lastUpdateTime = TNOW;
    //     int iRet = pConfigServant->ListRounterCfg(temp);
    //     if (iRet != 0)
    //     {
    //         ROLLLOG_ERROR << "load rounter info failed, iRet: " << iRet << endl;
    //         return false;
    //     }

    //     rsp.iLastVersion = temp.iLastVersion;
    //     rsp.data = temp.data;
    // }

    int iRet = pConfigServant->ListRounterCfg(rsp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "load rounter info failed" << endl;
        return false;
    }

    return true;
}

//网关信息
int Processor::UserRounter(const LoginProto::UserRounterInfoReq &req, LoginProto::UserRounterInfoResp &rsp)
{
    config::ListRounterCfgResp resp;
    if (!queryRounterForConfigServer(resp))
    {
        ROLLLOG_ERROR << "load rounter info failed: pConfigServant is null" << endl;
        rsp.set_routeraddr("");
        rsp.set_routerport(0);
        rsp.set_resultcode(XGameRetCode::INNER_ERROR);
        return XGameRetCode::INNER_ERROR;
    }

    if (resp.data.empty())
    {
        ROLLLOG_ERROR << "rounter list is empty" << endl;
        rsp.set_routeraddr("");
        rsp.set_routerport(0);
        rsp.set_resultcode(XGameRetCode::INNER_ERROR);
        return XGameRetCode::INNER_ERROR;
    }

    std::vector<config::RounterCfg> availableNode;
    for (auto iter = resp.data.begin(); iter != resp.data.end(); iter++)
    {
        auto &node = iter->second;
        if (0 == node.state)
            continue;

        availableNode.push_back(node);
    }

    if (availableNode.empty())
    {
        ROLLLOG_ERROR << "availableNode is empty." << endl;
        rsp.set_routeraddr("");
        rsp.set_routerport(0);
        rsp.set_resultcode(XGameRetCode::INNER_ERROR);
        return XGameRetCode::INNER_ERROR;
    }

    int random = rand() % availableNode.size();
    auto &node = availableNode[random];
    rsp.set_routeraddr(node.addr);
    rsp.set_routerport(node.port);
    rsp.set_resultcode(XGameRetCode::SUCCESS);
    return XGameRetCode::SUCCESS;
}

int Processor::ThirdPartyLogin(const LoginProto::ThirdPartyLoginReq &req, LoginProto::ThirdPartyLoginResp &rsp, const map<string, string> &extraInfo)
{
    LOG_DEBUG << "req:"<< logPb(req)<< endl;
    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.registerreq().username());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null" << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }
    //login addr
    string sRemoteIp = "";
    auto iter = extraInfo.find("RemoteIp");
    if (iter != extraInfo.end())
        sRemoteIp = (*iter).second;

    int iRet = authAppleLogin(req.token());
    if (0 != iRet)
    {
        ROLLLOG_ERROR << "thirdparty err. iRet:" << iRet  << endl;
        return iRet;
    }

    //查找帐号标识
    TGetRegisterInfoReq getRegisterReq;
    getRegisterReq.keyIndex = 0;
    getRegisterReq.tableName = "tb_useraccount";
    getRegisterReq.userName = req.registerreq().username();
    getRegisterReq.iThirdParty = 1;

    TGetRegisterInfoRsp getRegisterRsp;
    iRet = pDBAgentServant->getRegisterInfo(getRegisterReq, getRegisterRsp);
    ROLLLOG_DEBUG << "thirdparty register info, iRet: " << iRet << ", getRegisterRsp: " << printTars(getRegisterRsp) << endl;
    if ((iRet != 0) || (getRegisterRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "thirdparty register info err, iRet: " << iRet << ", iResult: " << getRegisterRsp.iResult << endl;
        rsp.set_resultcode(-1003);
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //获取用户标识
    int bNewUser = 0;
    tars::Int64 uid = getRegisterRsp.lUid;
    if (uid <= 0)
    {
        LoginProto::RegisterResp registerResp;
        int iRet = UserRegister2(req.registerreq(), registerResp, extraInfo);
        if (iRet != XGameRetCode::SUCCESS)
        {
            ROLLLOG_ERROR << "username: " << req.registerreq().username() << " iRet:" << iRet << endl;
            if (iRet == XGameRetCode::LOGIN_SERVER_ERROR)
            {
                return XGameRetCode::USER_INFO_PHONE_ALREADY_USED;
            }
            return iRet;
        }

        bNewUser = 1;
        uid = registerResp.uid();
    }

    LoginProto::UserLoginReq userLoginReq;
    LoginProto::UserLoginResp userLoginResp;
    userLoginReq.set_username(req.registerreq().username());
    userLoginReq.set_passwd(req.registerreq().username());
    userLoginReq.set_deviceid(req.registerreq().deviceid());
    iRet = UserLogin(userLoginReq, userLoginResp, extraInfo, 0);
    if (iRet != XGameRetCode::SUCCESS)
    {
        return iRet;
    }
    rsp.set_token(userLoginResp.token());
    rsp.set_need_safe_auth(userLoginResp.need_safe_auth());
    rsp.set_bind_phone(userLoginResp.bind_phone());
    rsp.set_bind_email(userLoginResp.bind_email());

    rsp.set_uid(uid);
    rsp.set_flag(bNewUser);
    return iRet;
}


int Processor::authAppleLogin(const std::string &tokenid)
{
    int iRet = 0;
    //string token = "eyJraWQiOiJlWGF1bm1MIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLm1hc3Rlci53b25kZXJwb2tlci5uZXciLCJleHAiOjE1OTgzNTIwMTgsImlhdCI6MTU5ODM1MTQxOCwic3ViIjoiMDAyMDEyLmE2NmYyZDBjNDliYzQ2YzM4OTQ2YzI5NzczOGI1NjI0LjA3MzciLCJjX2hhc2giOiJ3VnBCbUxiMnI1NGNZTzlXQndwTTd3IiwiZW1haWwiOiJ3dV9qdW55YW5nQHFxLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSIsImF1dGhfdGltZSI6MTU5ODM1MTQxOCwibm9uY2Vfc3VwcG9ydGVkIjp0cnVlfQ.M6lo0MNcwZMDnZB9PtmN6snSr5EaMsJ_X4OYLb8CaPsYYSkes_z6fT-Wpf99Zxe16W4sAfmdfvn-OEDJuqMfL6i6ETOa1lqTH0eT3942GhtCMQpH8a-84hjOBQ-ysLhIvuEF22o92TU_gOSWGJ3Qc5MsS0ESR9EZ7iiSN-8AeQaz5pV-DmMCK5phvI-9MhA4qahz-ED2eYblkX-zASa7F0YIvLWWg8U0kf-8fookaCYo0qNMCjTo0e0bHXkiKe_I3_aOSlSvedyaMk36Xs2nW0Ocvg37HNo1OFiJldl5phtDXfl5zxYmeEu5Ma6rQpU1BSgOt5rrL6Sk2j4NkPUqKA";
    auto decoded = jwt::decode(tokenid);
    //Get all payload claims
    std::ostringstream os;
    for (auto &e1 : decoded.get_payload_claims())
    {
        os << e1.first << " = " << e1.second.to_json() << std::endl;

        if ( e1.first == "aud" &&  e1.second.as_string() != "com.jinbeivip.club")
        {
            ROLLLOG_DEBUG << "first : " << e1.first << ", second:"<< e1.second.as_string() << endl;
            return -1;
        }

    }
    ROLLLOG_DEBUG << "payload : " << os.str() << endl;

    std::string kid;
    for (auto &e2 : decoded.get_header_claims())
    {
        if (e2.first == "kid")
        {
            kid = e2.second.as_string();
        }
    }

    //获取共钥
    std::string url = "https://appleid.apple.com/auth/keys";
    std::string respData;
    iRet = httpGet(url.c_str(), respData);
    if (0 != iRet || respData.empty())
    {
        ROLLLOG_ERROR << "load apple keys err. iRet:" << iRet << endl;
        return iRet;
    }

    Json::Reader Reader;
    Json::Value ReqKeyJson;
    Json::Value nn_an_ee;
    Reader.parse(respData, ReqKeyJson);
    for(auto key : ReqKeyJson["keys"])
    {
        if (key["kid"] == kid)
        {
            nn_an_ee = key;
        }
    }

    std::string strPubKey;
    bool bgetPublishKey = ConvertJwkToPem(nn_an_ee["n"].asString(), nn_an_ee["e"].asString(), strPubKey);
    if (!bgetPublishKey)
    {
        return -2;
    }
    //ROLLLOG_DEBUG << " strPubKey: "<< strPubKey <<endl;

    //共钥验证
    try
    {
        auto verifie = jwt::verify().allow_algorithm(jwt::algorithm::rs256(strPubKey, "", "", "")).with_issuer("https://appleid.apple.com");
        verifie.verify(decoded);

        /*        os.str("");
                for (auto &e : decoded.get_header_claims())
                    os << e.first << " = " << e.second.to_json() << std::endl;
                for (auto &e : decoded.get_payload_claims())
                    os << e.first << " = " << e.second.to_json() << std::endl;
                ROLLLOG_DEBUG<<"end:"<<os.str()<<endl;*/
    }
    catch (const std::exception &e)
    {
        ROLLLOG_DEBUG << "verify err. message: " << e.what() << endl;
        return -3;
    }

    return 0;
}

//将验证写入缓存中
int Processor::setAuthData(const std::string &phone, const std::string &smsCode)
{
    if (phone.empty() || smsCode.empty())
    {
        ROLLLOG_ERROR << "invalid sms data err, phone: " << phone << ", smscode: " << smsCode << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(phone);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    dataproxy::TWriteDataReq req;
    req.resetDefautlt();
    req.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_VERIFICATION_CODE) + ":" + phone;
    req.operateType = E_REDIS_WRITE;
    req.clusterInfo.resetDefautlt();
    req.clusterInfo.busiType = E_REDIS_PROPERTY;
    req.clusterInfo.frageFactorType = E_FRAGE_FACTOR_STRING;
    req.clusterInfo.frageFactor = tars::hash<string>()(phone);

    TField tfield;
    tfield.colArithType = E_NONE;
    tfield.colName = "token";
    tfield.colType = STRING;
    tfield.colValue = smsCode;
    req.fields.push_back(tfield);

    tfield.colArithType = E_NONE;
    tfield.colName = "time";
    tfield.colType = STRING;
    tfield.colValue = L2S(TNOW);
    req.fields.push_back(tfield);

    dataproxy::TWriteDataRsp rsp;
    int iRet = pDBAgentServant->redisWrite(req, rsp);
    if (iRet != 0 || rsp.iResult != 0)
    {
        ROLLLOG_ERROR << "save smscode data err, iRet: " << iRet << ", iResult: " << rsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    ROLLLOG_DEBUG << "set smscode data succ, iRet: " << iRet << ", wdataRsp: " << printTars(rsp) << ", code:" << smsCode << endl;
    return XGameRetCode::SUCCESS;
}

//从缓存中读取验证码
int Processor::getAuthData(const std::string &phone, std::string &ret, time_t &time)
{
    if (phone.empty())
    {
        ROLLLOG_ERROR << "invalid sms data err, phone: " << phone << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(phone);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    dataproxy::TReadDataReq req;
    req.resetDefautlt();
    req.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_VERIFICATION_CODE) + ":" + phone;
    req.operateType = E_REDIS_READ;
    req.clusterInfo.resetDefautlt();
    req.clusterInfo.busiType = E_REDIS_PROPERTY;
    req.clusterInfo.frageFactorType = E_FRAGE_FACTOR_STRING;
    req.clusterInfo.frageFactor = tars::hash<string>()(phone);

    TField tfield;
    tfield.colArithType = E_NONE;
    tfield.colName = "token";
    tfield.colType = STRING;
    req.fields.push_back(tfield);

    tfield.colArithType = E_NONE;
    tfield.colName = "time";
    tfield.colType = STRING;
    req.fields.push_back(tfield);

    TReadDataRsp rsp;
    int iRet = pDBAgentServant->redisRead(req, rsp);
    if (iRet != 0 || rsp.iResult != 0)
    {
        ROLLLOG_ERROR << "read data fail, iRet: " << iRet << ", iResult: " << rsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    bool bFind = false;
    for (auto it = rsp.fields.begin(); it != rsp.fields.end(); ++it)
    {
        for (auto itfields = it->begin(); itfields != it->end(); ++itfields)
        {
            if (itfields->colName == "token")
            {
                ret = itfields->colValue;
                bFind = true;
            }
            else if (itfields->colName == "time")
            {
                time = S2L(itfields->colValue);
                bFind = true;
            }
        }
    }

    if (!bFind)
    {
        ROLLLOG_ERROR << "read sms-code fail, iRet: " << iRet << ", iResult: " << rsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    ROLLLOG_DEBUG << "read sms-code succ, iRet: " << iRet << ", sms-code: " << ret << endl;
    return XGameRetCode::SUCCESS;
}

//从缓存中删除验证码
int Processor::delAuthData(const std::string &phone)
{
    if (phone.empty())
    {
        ROLLLOG_ERROR << "invalid sms data err, phone: " << phone << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(phone);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    dataproxy::TWriteDataReq req;
    req.resetDefautlt();
    req.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_VERIFICATION_CODE) + ":" + phone;
    req.operateType = E_REDIS_DELETE;
    req.clusterInfo.resetDefautlt();
    req.clusterInfo.busiType = E_REDIS_PROPERTY;
    req.clusterInfo.frageFactorType = E_FRAGE_FACTOR_STRING;
    req.clusterInfo.frageFactor = tars::hash<string>()(phone);

    dataproxy::TWriteDataRsp rsp;
    int iRet = pDBAgentServant->redisWrite(req, rsp);
    if (iRet != 0 || rsp.iResult != 0)
    {
        ROLLLOG_ERROR << "delete user auth data err, iRet: " << iRet << ", iResult: " << rsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    ROLLLOG_ERROR << "delete user auth data success, req.keyName: " << req.keyName << endl;

    return XGameRetCode::SUCCESS;
}

//添加密码错误次数
int Processor::addPasswordErrCount(const std::string &username)
{
    if (username.empty())
    {
        ROLLLOG_ERROR << "invalid sms data err, username: " << username << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(username);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    dataproxy::TWriteDataReq req;
    req.resetDefautlt();
    req.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_PASSWORD_ERROR) + ":" + username;
    req.operateType = E_REDIS_WRITE;
    req.clusterInfo.resetDefautlt();
    req.clusterInfo.busiType = E_REDIS_PROPERTY;
    req.clusterInfo.frageFactorType = E_FRAGE_FACTOR_STRING;
    req.clusterInfo.frageFactor = tars::hash<string>()(username);

    TField tfield;
    tfield.colArithType = E_ADD;
    tfield.colName = "count";
    tfield.colType = STRING;
    tfield.colValue = "1";
    req.fields.push_back(tfield);

    tfield.colArithType = E_NONE;
    tfield.colName = "time";
    tfield.colType = STRING;
    tfield.colValue = L2S(TNOW);
    req.fields.push_back(tfield);

    dataproxy::TWriteDataRsp rsp;
    int iRet = pDBAgentServant->redisWrite(req, rsp);
    if (iRet != 0 || rsp.iResult != 0)
    {
        ROLLLOG_ERROR << "save smscode data err, iRet: " << iRet << ", iResult: " << rsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    ROLLLOG_DEBUG << "set smscode data succ, iRet: " << iRet << ", wdataRsp: " << printTars(rsp) << endl;
    return XGameRetCode::SUCCESS;
}

//获取密码错误次数
int Processor::getPasswordErrCount(const std::string &username, int &errCount, time_t &time)
{
    if (username.empty())
    {
        ROLLLOG_ERROR << "invalid sms data err, username: " << username << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(username);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    dataproxy::TReadDataReq req;
    req.resetDefautlt();
    req.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_PASSWORD_ERROR) + ":" + username;
    req.operateType = E_REDIS_READ;
    req.clusterInfo.resetDefautlt();
    req.clusterInfo.busiType = E_REDIS_PROPERTY;
    req.clusterInfo.frageFactorType = E_FRAGE_FACTOR_STRING;
    req.clusterInfo.frageFactor = tars::hash<string>()(username);

    TField tfield;
    tfield.colArithType = E_NONE;
    tfield.colName = "count";
    tfield.colType = STRING;
    req.fields.push_back(tfield);

    tfield.colArithType = E_NONE;
    tfield.colName = "time";
    tfield.colType = STRING;
    req.fields.push_back(tfield);

    TReadDataRsp rsp;
    int iRet = pDBAgentServant->redisRead(req, rsp);
    if (iRet != 0 || rsp.iResult != 0)
    {
        ROLLLOG_ERROR << "read data fail, iRet: " << iRet << ", iResult: " << rsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    bool bFind = false;
    for (auto it = rsp.fields.begin(); it != rsp.fields.end(); ++it)
    {
        for (auto itfields = it->begin(); itfields != it->end(); ++itfields)
        {
            if (itfields->colName == "count")
            {
                errCount = S2L(itfields->colValue);
                bFind = true;
            }
            else if (itfields->colName == "time")
            {
                time = S2L(itfields->colValue);
                bFind = true;
            }
        }
    }

    if (!bFind)
    {
        ROLLLOG_ERROR << "read sms-code fail, iRet: " << iRet << ", iResult: " << rsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    return XGameRetCode::SUCCESS;
}

int Processor::delPasswordErrCount(const std::string &username)
{
    if (username.empty())
    {
        ROLLLOG_ERROR << "invalid sms data err, phone: " << username << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(username);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    dataproxy::TWriteDataReq req;
    req.resetDefautlt();
    req.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_PASSWORD_ERROR) + ":" + username;
    req.operateType = E_REDIS_DELETE;
    req.clusterInfo.resetDefautlt();
    req.clusterInfo.busiType = E_REDIS_PROPERTY;
    req.clusterInfo.frageFactorType = E_FRAGE_FACTOR_STRING;
    req.clusterInfo.frageFactor = tars::hash<string>()(username);

    dataproxy::TWriteDataRsp rsp;
    int iRet = pDBAgentServant->redisWrite(req, rsp);
    if (iRet != 0 || rsp.iResult != 0)
    {
        ROLLLOG_ERROR << "delete user auth data err, iRet: " << iRet << ", iResult: " << rsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    ROLLLOG_DEBUG << "delete user auth data success, req.keyName: " << req.keyName << endl;

    return XGameRetCode::SUCCESS;    
}

int Processor::setUserPassword(const std::string &username, const std::string &password)
{
    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(username);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    //根据username查找uid
    TGetRegisterInfoReq getRegisterReq;
    getRegisterReq.keyIndex = 0;
    getRegisterReq.tableName = "tb_useraccount";
    getRegisterReq.userName = username;

    TGetRegisterInfoRsp getRegisterRsp;
    int iRet = pDBAgentServant->getRegisterInfo(getRegisterReq, getRegisterRsp);
    ROLLLOG_DEBUG << "get user register info, iRet: " << iRet << ", getRegisterRsp: " << printTars(getRegisterRsp) << endl;
    if ((iRet != 0) || (getRegisterRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "get user register info err, iRet: " << iRet << ", iResult: " << getRegisterRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //uid不合法
    if (getRegisterRsp.lUid <= 0)
    {
        ROLLLOG_ERROR << "getRegisterRsp.lUid err, lUid: " << getRegisterRsp.lUid << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    userinfo::UpdateUserAccountReq updateUserAccountReq;
    updateUserAccountReq.uid = getRegisterRsp.lUid;
    updateUserAccountReq.updateInfo = {
        {"password", password},
    };
    userinfo::UpdateUserAccountResp updateUserAccountResp;
    iRet = g_app.getOuterFactoryPtr()->getHallServantPrx(updateUserAccountReq.uid)->updateUserAccount(updateUserAccountReq, updateUserAccountResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "updateUserAccount failed, uid: " << updateUserAccountReq.uid << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }
    return XGameRetCode::SUCCESS;
}

//产生uuid串
string Processor::generateUUIDStr()
{
    uuid_t uuid;
    uuid_generate(uuid);

    char buf[1024];
    memset(buf, 0, sizeof(buf));
    uuid_unparse(uuid, buf);

    string strRet;
    strRet.assign(buf, strlen(buf));
    return strRet;
}

/********************************************************
Description:    实现HTTP/HTTPS GET请求
********************************************************/
size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
    string data((const char *)ptr, (size_t)size * nmemb);
    *((stringstream *)stream) << data << endl;
    return size * nmemb;
}

/************************************
@ Brief:        GET请求
************************************/
int Processor::httpGet(const char *url, std::string &resJson)
{
    auto curl = curl_easy_init();
    if (!curl)
    {
        ROLLLOG_ERROR << "GET: curl is null" << endl;
        return XGameRetCode::LOGIN_GETHTTP_ERROR;
    }

    std::stringstream out;
    curl_easy_setopt(curl, CURLOPT_URL, url);

    // if (g_app.getOuterFactoryPtr()->getAgentOpenConfig())
    // {
    //     curl_easy_setopt(curl, CURLOPT_PROXY, "10.10.10.159:1081");
    // }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000);

    auto res = curl_easy_perform(curl);
    if (res != CURLE_OK)
    {
        ROLLLOG_ERROR << "curl_easy_perform failed: :" << curl_easy_strerror(res) << endl;
        curl_easy_cleanup(curl);
        return XGameRetCode::LOGIN_GETHTTP_ERROR;
    }

    ROLLLOG_DEBUG << "url :" << url << endl;
    ROLLLOG_DEBUG << "rsp :" << out.str() << endl;

    resJson = out.str();
    curl_easy_cleanup(curl);
    return 0;
}

/************************************
@ Brief: POST请求
************************************/
int Processor::httpPost(const char *url, const std::vector<std::string> &headerParams, const std::string &postParams, std::string &resJson)
{
    auto curl = curl_easy_init();
    if (!curl)
    {
        ROLLLOG_ERROR << "POST: curl is null" << endl;
        return XGameRetCode::LOGIN_GETHTTP_ERROR;
    }

    ROLLLOG_DEBUG << "post url :" << url << ", data: " << resJson << endl;

    curl_slist *header = nullptr;
    for (auto &it : headerParams)
    {
        header = curl_slist_append(header, it.c_str());
    }

    std::string debugLog;
    auto next = header;
    while (next != nullptr)
    {
        debugLog.append(next->data).append(" ");
        next = next->next;
    }

    std::stringstream out;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postParams.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000);
    auto res = curl_easy_perform(curl);
    if (res != CURLE_OK)
    {
        ROLLLOG_ERROR << "curl_easy_perform failed: :" << curl_easy_strerror(res) << endl;
        curl_easy_cleanup(curl);
        return XGameRetCode::LOGIN_GETHTTP_ERROR;
    }

    resJson = out.str();
    ROLLLOG_DEBUG << "httpPost succ: url=" << url << ", header:" << debugLog  << ", postData=" << postParams << ", resJson=" << resJson << endl;
    curl_slist_free_all(header);
    curl_easy_cleanup(curl);
    return 0;
}

bool Processor::ConvertJwkToPem(const std::string &strnn, const std::string &stree, std::string &strPubKey)
{
    auto nn = cppcodec::base64_url_unpadded::decode(strnn);
    auto ee = cppcodec::base64_url_unpadded::decode(stree);

    BIGNUM *modul = BN_bin2bn(nn.data(), nn.size(), NULL);
    BIGNUM *expon = BN_bin2bn(ee.data(), ee.size(), NULL);

    RSA *rr = RSA_new();
    EVP_PKEY *pRsaKey = EVP_PKEY_new();

    rr->n = modul;
    rr->e = expon;
    EVP_PKEY_assign_RSA(pRsaKey, rr);
    unsigned char *desc = new unsigned char[1024];
    memset(desc, 0, 1024);

    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, rr);
    BIO_read(bio, desc, 1024);
    strPubKey = (char *)desc;
    BIO_free(bio);
    RSA_free(rr);
    if (strPubKey.empty())
    {
        return false;
    }
    return true;
}

/**
 *  请求内容{"account":"N6000001",
 *    "password":"123456",
 *    "msg":"【253云通讯】您的验证码是2530",
 *    "phone":"15800000000",
 *    "sendtime":"201704101400",
 *    "report":"true",
 *    "extend":"555",
 *    "uid":"321abc"
 *  }
 * [Processor::sendAuthCode description]
 * @param  phone   [description]
 * @param  smsCode [description]
 * @return         [description]
 */
int Processor::sendAuthCode(const std::string &phone, const tars::Int32 &smsCode)
{
    if (phone.empty() || (smsCode <= 0))
    {
        ROLLLOG_ERROR << "param error, phone: " << phone << ", smsCode: " << smsCode << endl;
        return -1;
    }

    vector<string> details = split(phone, "-");
    if ((int)details.size() != 2)
    {
        ROLLLOG_ERROR << "param error, phone: " << phone << endl;
        return -1;
    }

    int iRet = XGameRetCode::SUCCESS;
    std::string respData;
    std::string str = I2S(smsCode);

    std::string strArea = details[0];
    std::string strPhone = details[1];
    std::string strAuthPhone = "";
    std::vector<std::string> headerParams;

    if (strArea == "86")
    {
        strAuthPhone = strPhone;//国内手机号无区号

        auto &sms = g_app.getOuterFactoryPtr()->getSMSConfig();
        std::string sMsg = replace(sms.content, "msg", str.c_str());
        
        headerParams.push_back("content-type:application/json;charset=utf-8");
        std::string time = CurTimeFormat();
        std::string md5 = tars::TC_MD5::md5str(sms.password + time);

        char buffer[2048] = {'\0'};
        sprintf(buffer, "{\"uid\":\"%s\",\"pw\":\"%s\",\"tm\":\"%s\",\"data\":[{\"mb\":\"%s\",\"ms\":\"%s\"}]}",
                sms.account.c_str(), md5.c_str(), time.c_str(), strAuthPhone.c_str(), sMsg.c_str());

        ROLLLOG_DEBUG << "post data: " << buffer << endl;

        iRet = httpPost(sms.sendURL.c_str(), headerParams, buffer, respData);
        if ((XGameRetCode::SUCCESS != iRet) || respData.empty())
        {
            ROLLLOG_ERROR << "httpPost failed, iRet: " << iRet << ", respData:" << respData << endl;
            return iRet;
        }

        Json::Value retJson;
        Json::Reader reader;
        reader.parse(respData, retJson);
        auto &jsonValue = retJson["status"];
        if (jsonValue.isInt())
            iRet = jsonValue.asInt();
        else if (jsonValue.isString())
            iRet = S2I(jsonValue.asString());
        else
            iRet = XGameRetCode::INNER_ERROR;
    }
    else
    {
        strAuthPhone = strArea + strPhone;//海外手机号带区号

        std::string sMsg = "";
        auto &smsOversea = g_app.getOuterFactoryPtr()->getSMSConfigOversea();
        sMsg = replace(smsOversea.content, "msg", str.c_str());

        char buffer[2048] = {'\0'};
        sprintf(buffer, "mocean-api-key=%s&mocean-api-secret=%s&mocean-from=%s&mocean-to=%s&mocean-text=%s",
                smsOversea.account.c_str(), smsOversea.password.c_str(), smsOversea.appid.c_str(), strAuthPhone.c_str(), sMsg.c_str());

        ROLLLOG_DEBUG << "Oversea post data: " << buffer << endl;

        iRet = httpPost(smsOversea.sendURL.c_str(), headerParams, buffer, respData);
        if ((XGameRetCode::SUCCESS != iRet) || respData.empty())
        {
            ROLLLOG_ERROR << "httpPost failed, iRet: " << iRet << ", respData:" << respData << endl;
            return iRet;
        }

        // respData = "<?xml version=\"1.0\"?><result><messages><message><status>0</status><receiver>85297193964</receiver><msgid>qzkjops0630113258934625.0001</msgid></message></messages></result>";

        tinyxml2::XMLDocument xmlDoc;
        xmlDoc.Parse(respData.c_str());
        const char *title = xmlDoc.FirstChildElement("result")->FirstChildElement("messages")->FirstChildElement("message")->FirstChildElement("status")->GetText();
        iRet = S2I(title);
    }

    if (XGameRetCode::SUCCESS != iRet)
    {
        ROLLLOG_ERROR << "send phone code fail: respData=" << respData << endl;
        if (iRet == 2) //余额不足
        {
            ROLLLOG_ERROR << "Insufficient balance. iRet =" << iRet << endl;
            return XGameRetCode::USER_INFO_PHOME_SERVICE_UNAVAILABLE;
        }
        return iRet;
    }

    ROLLLOG_DEBUG << "httpPost succ, iRet: " << iRet << ", respData:" << respData << endl;
    return XGameRetCode::SUCCESS;
}

string Processor::getCountryByIP(const string &ip)
{
    string country_id = ServiceUtil::get_country_by_ip(ip);
    ROLLLOG_DEBUG << "ip:"<< ip << ", country_id: "<< country_id << endl;
    return country_id;
}


int Processor::GetServerUpdateTime(LoginProto::GetServerUpdateTimeResp &rsp)
{
    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(10000);
    if (!pDBAgentServant)
    {
        return XGameRetCode::LOGIN_USER_SERVER_UPDATE;
    }

    //查询维护时间
    int keyIndex = 10000;

    dataproxy::TReadDataReq dataReq;
    dataReq.resetDefautlt();
    dataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(SERVER_UPDATE) + ":" + L2S(keyIndex);
    dataReq.operateType = E_REDIS_READ;
    dataReq.clusterInfo.resetDefautlt();
    dataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
    dataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
    dataReq.clusterInfo.frageFactor = keyIndex;

    vector<TField> fields;
    TField tfield;
    tfield.colArithType = E_NONE;
    tfield.colName = "begin_time";
    tfield.colType = BIGINT;
    fields.push_back(tfield);
    tfield.colName = "end_time";
    tfield.colType = BIGINT;
    fields.push_back(tfield);
    dataReq.fields = fields;

    TReadDataRsp dataRsp;
    int iRet = pDBAgentServant->redisRead(dataReq, dataRsp);
    ROLLLOG_DEBUG << "get server update, iRet: " << iRet << ", dataRsp: " << printTars(dataRsp) << endl;
    if (iRet != 0 || dataRsp.iResult != 0)
    {
        ROLLLOG_ERROR << "get server update, iRet: " << iRet << ", iResult: " << dataRsp.iResult << endl;
        return XGameRetCode::LOGIN_USER_SERVER_UPDATE;
    }

    long beginTime = 0;
    long endTime = 0;
    for (auto it = dataRsp.fields.begin(); it != dataRsp.fields.end(); ++it)
    {
        for (auto ituid = it->begin(); ituid != it->end(); ++ituid)
        {
            if (ituid->colName == "begin_time")
            {
                beginTime = S2L(ituid->colValue);
            }
            else if (ituid->colName == "end_time")
            {
                endTime = S2L(ituid->colValue);
            }
        }
    }

    rsp.set_begintime(beginTime);
    rsp.set_endtime(endTime);

    LOG_DEBUG << "beginTime:"<< beginTime << ", endTime:"<< endTime << ", nowTime:"<< TNOW << endl;

    return 0;
}
