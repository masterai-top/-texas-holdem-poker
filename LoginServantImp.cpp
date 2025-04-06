#include "LoginServantImp.h"
#include "servant/Application.h"
#include "LogComm.h"
#include "globe.h"
#include "XGameComm.pb.h"
#include "XGameHttp.pb.h"
#include "CommonCode.pb.h"
#include "CommonStruct.pb.h"
#include "UserInfo.pb.h"
#include "login.pb.h"
#include "DataProxyProto.h"
#include "ServiceDefine.h"
#include "util/tc_hash_fun.h"
#include "LoginServer.h"
#include "Processor.h"
#include "LogDefine.h"
#include "Push.h"
#include "uuid.h"
#include <regex>

//
using namespace std;
using namespace JFGame;
using namespace login;
using namespace dataproxy;
using namespace userinfo;

//////////////////////////////////////////////////////
void LoginServantImp::initialize()
{
    //initialize servant here:
    //...
}

//////////////////////////////////////////////////////
void LoginServantImp::destroy()
{
    //destroy servant here:
    //...
}

//http请求处理接口
tars::Int32 LoginServantImp::doRequest(const vector<tars::Char> &reqBuf, const map<std::string, std::string> &extraInfo,
                                       vector<tars::Char> &rspBuf, tars::TarsCurrentPtr current)
{
    FUNC_ENTRY("");

    int iRet = 0;

    __TRY__

    if (reqBuf.empty())
    {
        iRet = -1;
        return iRet;
    }

    XGameHttp::THttpPackage thttpPack;

    __TRY__
    if (!reqBuf.empty())
    {
        pbToObj(reqBuf, thttpPack);
    }
    __CATCH__

    if (thttpPack.vecdata().empty())
    {
        iRet = -2;
        LOG_ERROR << " data is empty. "<< endl;
        return iRet;
    }

    int64_t ms1 = TNOWMS;

    XGameHttp::THttpPackage thttpPackRsp;
    switch (thttpPack.nmsgid())
    {
    // 网关信息
    case XGameProto::ActionName::USER_ROUNTER:
    {
        LoginProto::UserRounterInfoReq rounterReq;
        LoginProto::UserRounterInfoResp routerResp;
        pbToObj(thttpPack.vecdata(), rounterReq);
        iRet = ProcessorSingleton::getInstance()->UserRounter(rounterReq, routerResp);
        routerResp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(routerResp));
        break;
    }
    // 帐号登出
    case XGameProto::ActionName::LOGIN_LOGOUT:
    {
        LoginProto::LogoutReq logoutReq;
        pbToObj(thttpPack.vecdata(), logoutReq);
        LoginProto::LogoutResp logoutResp;
        iRet = ProcessorSingleton::getInstance()->UserLogout(logoutReq, logoutResp);
        logoutResp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(logoutResp));
        break;
    }
    //快速登录
    case XGameProto::ActionName::LOGIN_QUICK:
    {
        LoginProto::QuickLoginReq quickLoginReq;
        pbToObj(thttpPack.vecdata(), quickLoginReq);
        LoginProto::QuickLoginResp quickLoginResp;
        iRet = ProcessorSingleton::getInstance()->QuickLogin(quickLoginReq, quickLoginResp, extraInfo);
        quickLoginResp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(quickLoginResp));
        break;
    }
    // 设备登录
    case XGameProto::ActionName::LOGIN_DEVICE:
    {
        LoginProto::DeviceLoginReq deviceLoginReq;
        pbToObj(thttpPack.vecdata(), deviceLoginReq);
        LoginProto::DeviceLoginResp deviceLoginResp;
        iRet = ProcessorSingleton::getInstance()->DeviceLogin(deviceLoginReq, deviceLoginResp, extraInfo, thttpPack.iver());
        deviceLoginResp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(deviceLoginResp));
        break;
    }
     // 设备升级
    case XGameProto::ActionName::DEVICE_UPGRADE:
    {
        LoginProto::DeviceUpgradeReq deviceUpgradeReq;
        pbToObj(thttpPack.vecdata(), deviceUpgradeReq);
        LoginProto::DeviceUpgradeResp deviceUpgradeResp;
        iRet = ProcessorSingleton::getInstance()->DeviceUpgrade(deviceUpgradeReq, deviceUpgradeResp, extraInfo);
        deviceUpgradeResp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(deviceUpgradeResp));
        break;
    }
    // 手机注册
    case XGameProto::ActionName::LOGIN_PHONE_ACCOUNT_REGISTER:
    {
        LoginProto::PhoneRegisterReq phoneRegisterReq;
        pbToObj(thttpPack.vecdata(), phoneRegisterReq);
        LoginProto::PhoneRegisterResp phoneRegisterRsp;
        iRet = ProcessorSingleton::getInstance()->PhoneRegister(phoneRegisterReq, phoneRegisterRsp, extraInfo);
        phoneRegisterRsp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(phoneRegisterRsp));
        break;
    }
    // 手机登录
    case XGameProto::ActionName::LOGIN_PHONE_ACCOUNT:
    {
        LoginProto::PhoneLoginReq phoneLoginReq;
        pbToObj(thttpPack.vecdata(), phoneLoginReq);
        LoginProto::PhoneLoginResp phoneLoginRsp;
        iRet = ProcessorSingleton::getInstance()->PhoneLogin(phoneLoginReq, phoneLoginRsp, extraInfo, thttpPack.iver());
        phoneLoginRsp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(phoneLoginRsp));
        break;
    }
    //手机重置密码 
    case XGameProto::ActionName::LOGIN_PHONE_ACCOUNT_RESET_PASSWD:
    {
        LoginProto::PhoneModifyPasswordReq phonepasswordReq;
        pbToObj(thttpPack.vecdata(), phonepasswordReq);
        LoginProto::PhoneModifyPasswordResp phonepasswordRsp;
        iRet = ProcessorSingleton::getInstance()->PhoneResetPassword(phonepasswordReq, phonepasswordRsp);
        phonepasswordRsp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(phonepasswordRsp));
        break;
    }
    // 手机验证码
    case XGameProto::ActionName::USER_SEND_PHONE_CODE:
    {
        LoginProto::SendPhoneMessageCodeReq phoneMsgCodeReq;
        pbToObj(thttpPack.vecdata(), phoneMsgCodeReq);
        LoginProto::SendPhoneMessageCodeResp phoneMsgCodeRsp;
        iRet = ProcessorSingleton::getInstance()->PhoneMsgCode(phoneMsgCodeReq, phoneMsgCodeRsp);
        phoneMsgCodeRsp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(phoneMsgCodeRsp));
        break;
    }
    case XGameProto::ActionName::LOGIN_EMAIL:
    {
        LoginProto::UserLoginReq userLoginReq;
        LoginProto::UserLoginResp userLoginResp;
        pbToObj(thttpPack.vecdata(), userLoginReq);
        iRet = ProcessorSingleton::getInstance()->EmailLogin(userLoginReq, userLoginResp, extraInfo, thttpPack.iver());
        userLoginResp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(userLoginResp));
        break;
    }
    case XGameProto::ActionName::EMAIL_REGISTER:
    {
        LoginProto::EmailRegisterReq registerReq;
        pbToObj(thttpPack.vecdata(), registerReq);
        LoginProto::EmailRegisterResp registerRsp;
        iRet = ProcessorSingleton::getInstance()->EmailRegister(registerReq, registerRsp, extraInfo);
        registerRsp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(registerRsp));
        break;
    }
    case XGameProto::ActionName::EMAIL_RESET_PASSWORD:
    {
        LoginProto::EmailModifyPasswordReq passwordReq;
        pbToObj(thttpPack.vecdata(), passwordReq);
        LoginProto::EmailModifyPasswordResp passwordRsp;
        iRet = ProcessorSingleton::getInstance()->EmailResetPassword(passwordReq, passwordRsp);
        passwordRsp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(passwordRsp));
        break;
    }
    case XGameProto::ActionName::EMAIL_SEND_AUTH_CODE:
    {
        LoginProto::SendEmailMessageCodeReq emailMsgCodeReq;
        pbToObj(thttpPack.vecdata(), emailMsgCodeReq);
        LoginProto::SendEmailMessageCodeResp emailMsgCodeRsp;
        iRet = ProcessorSingleton::getInstance()->EmailMsgCode(emailMsgCodeReq, emailMsgCodeRsp);
        emailMsgCodeRsp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(emailMsgCodeRsp));
        break;
    }
    case XGameProto::ActionName::VERIFY_AUTH_CODE:
    {
        LoginProto::VerifyAuthCodeReq verifyAuthCodeReq;
        pbToObj(thttpPack.vecdata(), verifyAuthCodeReq);
        LoginProto::VerifyAuthCodeResp verifyAuthCodeResp;
        iRet = ProcessorSingleton::getInstance()->VerifyAuthCode(verifyAuthCodeReq, verifyAuthCodeResp);
        verifyAuthCodeResp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(verifyAuthCodeResp));
        break;
    }
    case XGameProto::ActionName::REGISTER_USERINFO:
    {
        LoginProto::RegisterUserInfoReq registerUserInfoReq;
        pbToObj(thttpPack.vecdata(), registerUserInfoReq);
        LoginProto::RegisterUserInfoResp registerUserInfoResp;
        iRet = ProcessorSingleton::getInstance()->RegisterUserInfo(registerUserInfoReq);
        registerUserInfoResp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(registerUserInfoResp));
        break;
    }
    case XGameProto::ActionName::VERIFY_USERNAME:
    {
        LoginProto::CheckUserAccountReq checkUserAccountReq;
        pbToObj(thttpPack.vecdata(), checkUserAccountReq);
        LoginProto::CheckUserAccountResp checkUserAccountResp;
        long uid  = ProcessorSingleton::getInstance()->getAccountUid(checkUserAccountReq.username());
        if(uid <= 0)
        {
            iRet = XGameRetCode::USER_INFO_PHONE_ACCOUNT_NOT_EXSIT;
        }
        checkUserAccountResp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(checkUserAccountResp));
        break;
    }
    //第三方登录
    case XGameProto::ActionName::LOGIN_GOOGLE:
    case XGameProto::ActionName::LOGIN_FACEBOOK:
    case XGameProto::ActionName::LOGIN_APPLE:
    {
        LoginProto::ThirdPartyLoginReq thirdLoginReq;
        pbToObj(thttpPack.vecdata(), thirdLoginReq);
        LoginProto::ThirdPartyLoginResp thirdLoginResp;
        iRet = ProcessorSingleton::getInstance()->ThirdPartyLogin(thirdLoginReq, thirdLoginResp, extraInfo);
        thirdLoginResp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(thirdLoginResp));
        break;
    }
    case XGameProto::ActionName::GET_SERVER_UPDATE_TIME:
    {
        LoginProto::GetServerUpdateTimeResp getServerUpdateTimeResp;
        ProcessorSingleton::getInstance()->GetServerUpdateTime(getServerUpdateTimeResp);
        getServerUpdateTimeResp.set_resultcode(0);
        thttpPackRsp.set_vecdata(pbToString(getServerUpdateTimeResp));
        break;
    }
    //异常
    default:
    {
        ROLLLOG_ERROR << "invalid msgid:"<< thttpPack.nmsgid() << endl;
        iRet = -101;
        return iRet;
    }
    }

    int64_t ms2 = TNOWMS;
    if ((ms2 - ms1) > COST_MS)
    {
        ROLLLOG_WARN << "@Performance, msgid:" << thttpPack.nmsgid() << ", costTime:" << (ms2 - ms1) << endl;
    }

    ROLLLOG_DEBUG << "recv msg, msgid : " << thttpPack.nmsgid() << ", iRet: " << iRet << endl;

    auto ptuid = thttpPackRsp.mutable_stuid();
    ptuid->set_luid(thttpPack.stuid().luid());
    ptuid->set_stoken(thttpPack.stuid().stoken());

    thttpPackRsp.set_iver(thttpPack.iver());
    thttpPackRsp.set_iseq(thttpPack.iseq());
    thttpPackRsp.set_nmsgid(thttpPack.nmsgid());
    pbTobuffer(thttpPackRsp, rspBuf);

    ROLLLOG_DEBUG << "response buff size: " << rspBuf.size() << endl;

    __CATCH__;
    FUNC_EXIT("", iRet);
    return iRet;
}

//tcp请求处理接口
tars::Int32 LoginServantImp::onRequest(tars::Int64 lUin, const std::string &sMsgPack, const std::string &sCurServrantAddr, const JFGame::TClientParam &stClientParam, const JFGame::UserBaseInfoExt &stUserBaseInfo,
                                       tars::TarsCurrentPtr current)
{
    int iRet = 0;

    __TRY__

    ROLLLOG_DEBUG << "recv msg, uid : " << lUin << ", addr : " << stClientParam.sAddr << endl;

    LoginServant::async_response_onRequest(current, 0);

    //解码
    XGameComm::TPackage pkg;
    pbToObj(sMsgPack, pkg);

    //无数据
    if (pkg.vecmsghead_size() == 0)
    {
        ROLLLOG_DEBUG << "package empty." << endl;
        return -1;
    }

    ROLLLOG_DEBUG << "recv msg, uid : " << lUin << ", msg : " << logPb(pkg) << endl;

    //消息分发处理
    for (int i = 0; i < pkg.vecmsghead_size(); ++i)
    {
        int64_t ms1 = TNOWMS;

        const XGameComm::TMsgHead &head = pkg.vecmsghead(i);
        switch (head.nmsgid())
        {
        // 账号登录
        case XGameProto::ActionName::USER_LOGIN:
        {
            break;
        }
        // 账号注册
        case XGameProto::ActionName::USER_REGISTER:
        {
            break;
        }
        // 账号登出
        case XGameProto::ActionName::LOGIN_LOGOUT:
        {
            LoginProto::LogoutReq logoutReq;
            logoutReq.set_uid(pkg.stuid().luid());
            iRet = onUserLogout(pkg, logoutReq, sCurServrantAddr);
            break;
        }
        // 设备登录
        case XGameProto::ActionName::LOGIN_DEVICE:
        {
            break;
        }
        // 手机登录
        case XGameProto::ActionName::LOGIN_PHONE_ACCOUNT:
        {
            break;
        }
        // 手机验证码
        case XGameProto::ActionName::USER_SEND_PHONE_CODE:
        {
            LoginProto::SendPhoneMessageCodeReq msgCodeReq;
            pbToObj(pkg.vecmsgdata(i), msgCodeReq);
            iRet = onSendPhoneMsgCode(pkg, msgCodeReq, sCurServrantAddr, stClientParam, stUserBaseInfo);
            break;
        }
         // 邮箱验证码
        case XGameProto::ActionName::EMAIL_SEND_AUTH_CODE:
        {
            LoginProto::SendEmailMessageCodeReq msgCodeReq;
            pbToObj(pkg.vecmsgdata(i), msgCodeReq);
            iRet = onSendEmailMsgCode(pkg, msgCodeReq, sCurServrantAddr, stClientParam, stUserBaseInfo);
            break;
        }
        // 在线用户零点更新
        case XGameProto::ActionName::USER_STATE_ZERO_ONLINE_UPDATE:
        {
            break;
        }
        // 用户行为上报统计
        case XGameProto::ActionName::USER_ACTION_REPORT_STATISTICS:
        {
            break;
        }
        //异常处理
        default:
        {
            ROLLLOG_ERROR << "invalid msg id, uid: " << lUin << ", msg id: " << head.nmsgid() << endl;
            break;
        }
        }

        int64_t ms2 = TNOWMS;
        if ((ms2 - ms1) > COST_MS)
        {
            ROLLLOG_WARN << "@Performance, msgid:" << head.nmsgid() << ", costTime:" << (ms2 - ms1) << endl;
        }

        ROLLLOG_DEBUG << "recv msg, msgid : " << head.nmsgid() << ", iRet: " << iRet << endl;
    }

    __CATCH__;
    return iRet;
}

//校验token
tars::Int32 LoginServantImp::checkLoginToken(const login::CheckLoginTokenReq &req, login::CheckLoginTokenResp &resp, tars::TarsCurrentPtr current)
{

    LOG_ERROR << "checkLoginToken" << endl;

    if (req.lUid < 0 || req.sToken.empty())
    {
        ROLLLOG_ERROR << "paramter err, uid: " << req.lUid << ", token: " << req.sToken << endl;
        resp.resultCode = XGameRetCode::ARG_NULL_ERROR;
        resp.sHallId = "";
        return XGameRetCode::ARG_NULL_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.lUid);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null, uid: " << req.lUid << ", token: " << req.sToken << endl;
        resp.resultCode = XGameRetCode::ARG_NULL_ERROR;
        resp.sHallId = "";
        return XGameRetCode::ARG_NULL_ERROR;
    }

    userinfo::GetUserAccountReq userAccountReq;
    userAccountReq.uid = req.lUid;
    userinfo::GetUserAccountResp userAccountResp;
    int iRet = g_app.getOuterFactoryPtr()->getHallServantPrx(userAccountReq.uid)->getUserAccount(userAccountReq, userAccountResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "getUserAccount failed, uid: " << userAccountReq.uid << endl;
        resp.resultCode = -1;
        return XGameRetCode::LOGIN_TOKEN_INCONSISTENT;
    }

    string sztoken = "";
    long exptime = 0;
    //查询token
    {
        dataproxy::TReadDataReq dataReq;
        dataReq.resetDefautlt();
        dataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(req.lUid);
        dataReq.operateType = E_REDIS_READ;
        dataReq.clusterInfo.resetDefautlt();
        dataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
        dataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
        dataReq.clusterInfo.frageFactor = req.lUid;

        vector<TField> fields;
        TField tfield;
        tfield.colArithType = E_NONE;
        tfield.colName = "token";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "exptime";
        tfield.colType = BIGINT;
        fields.push_back(tfield);
        dataReq.fields = fields;

        TReadDataRsp dataRsp;
        int iRet = pDBAgentServant->redisRead(dataReq, dataRsp);
        ROLLLOG_DEBUG << "get user token data, uid: " << req.lUid << ", iRet: " << iRet << ", dataRsp: " << printTars(dataRsp) << endl;
        if (iRet != 0 || dataRsp.iResult != 0)
        {
            ROLLLOG_ERROR << "get user token err, uid: " << req.lUid << ", iRet: " << iRet << ", iResult: " << dataRsp.iResult << endl;
            resp.resultCode = XGameRetCode::LOGIN_SERVER_ERROR;
            resp.sHallId = "";
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        for (auto it = dataRsp.fields.begin(); it != dataRsp.fields.end(); ++it)
        {
            for (auto ituid = it->begin(); ituid != it->end(); ++ituid)
            {
                if (ituid->colName == "token")
                {
                    sztoken = ituid->colValue;
                }
                else if (ituid->colName == "exptime")
                {
                    exptime = S2L(ituid->colValue);
                }
            }
        }
    }

    //不合法
    if (req.sToken != sztoken)
    {
        resp.resultCode = XGameRetCode::LOGIN_TOKEN_INCONSISTENT;
        resp.sHallId = "";
        ROLLLOG_DEBUG << "invalid token, uid: " << req.lUid << ", req token: " << req.sToken << ", fact token: " << sztoken << endl;
        return XGameRetCode::LOGIN_TOKEN_INCONSISTENT;
    }

    if (exptime < time(NULL))
    {
        resp.resultCode = XGameRetCode::LOGIN_TOKEN_EXPIRED;
        resp.sHallId = "";
        ROLLLOG_DEBUG << "expired token, uid: " << req.lUid << ",sToken: " << req.sToken << ", exptime: " << exptime << ", now :" << time(NULL) << endl;
        return XGameRetCode::LOGIN_TOKEN_EXPIRED;
    }

    //用户登录日志
    vector<string> vLogLogin;
    vLogLogin.push_back(I2S(APP_ID));
    vLogLogin.push_back("1001");
    vLogLogin.push_back("0");
    vLogLogin.push_back("0");
    vLogLogin.push_back("0");
    vLogLogin.push_back(L2S(req.lUid));
    vLogLogin.push_back("");
    vLogLogin.push_back(req.sRemoteIP);
    vLogLogin.push_back("3");
    vLogLogin.push_back("0");
    g_app.getOuterFactoryPtr()->asyncLog2DB(req.lUid, 21, vLogLogin);

    ProcessorSingleton::getInstance()->updateUserLoginTime(req.lUid, "last_login_time");

    //合法
    resp.resultCode = XGameRetCode::SUCCESS;
    resp.sHallId = "";
    return XGameRetCode::SUCCESS;
}

//账号注册
tars::Int32 LoginServantImp::Register(const login::RegisterReq &req, login::RegisterResp &resp, tars::TarsCurrentPtr current)
{
    int iRet = 0;
    FUNC_ENTRY("");
    __TRY__

    __CATCH__;
    FUNC_EXIT("", iRet);
    return iRet;
}

//账号退出
tars::Int32 LoginServantImp::Logout(const login::UserLogoutReq &req, login::UserLogoutResp &resp, tars::TarsCurrentPtr current)
{
    int iRet = 0;
    FUNC_ENTRY("");
    __TRY__

    LOG_DEBUG << "req: "<< printTars(req)<< endl;

    iRet = ProcessorSingleton::getInstance()->updateUserLoginTime(req.uid, "last_logout_time");

    resp.resultCode = iRet;
    __CATCH__;
    FUNC_EXIT("", iRet);
    return iRet;
}

//用户状态变化
tars::Int32 LoginServantImp::UserState(const long uid, const int state, tars::TarsCurrentPtr current)
{
    ROLLLOG_DEBUG << "user state change, uid: " << uid << ", state: " << state << endl;
    return 0;
}

#define MIN_USERNAME_LEN 1           //用户名长度
#define MIN_PASSWD_LEN 4             //密码长度
#define MAX_UID_NUMBER_PER_ACCOUNT 1 //每个账号对应一个uid

//登出
int LoginServantImp::onUserLogout(const XGameComm::TPackage &pkg, const LoginProto::LogoutReq &logoutReq, const std::string &sCurServrantAddr)
{
    long consumStartMs = TNOWMS;
    FUNC_ENTRY("");
    int iRet = 0;

    __TRY__

    LoginProto::LogoutResp logoutResp;
    iRet = ProcessorSingleton::getInstance()->UserLogout(logoutReq, logoutResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "logout err, uid: " << logoutReq.uid() << ", iRet: " << iRet << endl;
    }

    logoutResp.set_resultcode(iRet);
    toClientPb(pkg, sCurServrantAddr, XGameProto::ActionName::LOGIN_LOGOUT, logoutResp);

    __CATCH__;
    FUNC_EXIT("", iRet);
    FUNC_COST_MS(consumStartMs)
    return iRet;
}

//发送手机验证码
tars::Int32 LoginServantImp::onSendPhoneMsgCode(const XGameComm::TPackage pkg, const LoginProto::SendPhoneMessageCodeReq &req, const std::string &sCurServrantAddr,
        const JFGame::TClientParam &stClientParam, const JFGame::UserBaseInfoExt &stUserBaseInfo)
{
    long consumStartMs = TNOWMS;
    FUNC_ENTRY("");

    LoginProto::SendPhoneMessageCodeResp rsp;
    int iRet = ProcessorSingleton::getInstance()->PhoneMsgCode(req, rsp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "send phone code err, phone: " << req.phone() << ", iRet: " << iRet << endl;
    }

    rsp.set_resultcode(iRet);
    toClientPb(pkg, sCurServrantAddr, XGameProto::ActionName::USER_SEND_PHONE_CODE, rsp);
    FUNC_EXIT("", iRet);
    FUNC_COST_MS(consumStartMs)
    return iRet;
}

//发送邮箱验证码
tars::Int32 LoginServantImp::onSendEmailMsgCode(const XGameComm::TPackage pkg, const LoginProto::SendEmailMessageCodeReq &req, const std::string &sCurServrantAddr,
        const JFGame::TClientParam &stClientParam, const JFGame::UserBaseInfoExt &stUserBaseInfo)
{
    long consumStartMs = TNOWMS;
    FUNC_ENTRY("");

    LoginProto::SendEmailMessageCodeResp rsp;
    int iRet = ProcessorSingleton::getInstance()->EmailMsgCode(req, rsp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "send phone code err, email: " << req.email() << ", iRet: " << iRet << endl;
    }

    rsp.set_resultcode(iRet);
    toClientPb(pkg, sCurServrantAddr, XGameProto::ActionName::EMAIL_SEND_AUTH_CODE, rsp);
    FUNC_EXIT("", iRet);
    FUNC_COST_MS(consumStartMs)
    return iRet;
}

//发送消息到客户端
template <typename T>
int LoginServantImp::toClientPb(const XGameComm::TPackage &tPackage, const std::string &sCurServrantAddr, XGameProto::ActionName actionName, const T &t)
{
    XGameComm::TPackage rsp;
    rsp.set_iversion(tPackage.iversion());
    rsp.mutable_stuid()->set_luid(tPackage.stuid().luid());
    rsp.set_igameid(tPackage.igameid());
    rsp.set_sroomid(tPackage.sroomid());
    rsp.set_iroomserverid(tPackage.iroomserverid());
    rsp.set_isequence(tPackage.isequence());
    rsp.set_iflag(tPackage.iflag());

    auto mh = rsp.add_vecmsghead();
    mh->set_nmsgid(actionName);
    mh->set_nmsgtype(XGameComm::MSGTYPE::MSGTYPE_RESPONSE);
    mh->set_servicetype(XGameComm::SERVICE_TYPE::SERVICE_TYPE_LOGIN);
    rsp.add_vecmsgdata(pbToString(t));

    auto pPushPrx = Application::getCommunicator()->stringToProxy<JFGame::PushPrx>(sCurServrantAddr);
    if (pPushPrx)
    {
        ROLLLOG_DEBUG << "toClientPb, uid: " << tPackage.stuid().luid() << ", actionName: " << actionName << ", toclient pb: " << logPb(rsp) << ", t: " << logPb(t) << endl;
        pPushPrx->tars_hash(tPackage.stuid().luid())->async_doPushBuf(NULL, tPackage.stuid().luid(), pbToString(rsp));
    }
    else
    {
        ROLLLOG_ERROR << "pPushPrx is null, uid: " << tPackage.stuid().luid() << ", actionName: " << actionName << ", toclient pb: " << logPb(rsp) << ", t: " << logPb(t) << endl;
    }

    return 0;
}

//产生uuid串
string LoginServantImp::generateUUIDStr()
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
