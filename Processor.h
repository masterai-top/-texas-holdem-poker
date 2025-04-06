#ifndef _Processor_H_
#define _Processor_H_

#include <util/tc_singleton.h>
#include "login.pb.h"
#include "LoginProto.h"
#include <curl/curl.h>
#include <json/json.h>
#include <future>
#include "UserInfoProto.h"
#include "CommonStruct.pb.h"
//
using namespace tars;

/**
 *请求处理类
 *
 */
class Processor
{
public:
    Processor();
    ~Processor();

public:
    //
    int updateUserLoginTime(long uid, const string name);
    //
    int updateUserAccountInfo(long uid, const string &sRemoteIp, const string &deviceid, int flag = 1, const int iPlatform = 0, const int iSysVersion = 0);
    //
    int checkWhiteList(const long lPlayerID);
    //登出
    int UserLogout(const LoginProto::LogoutReq &req, LoginProto::LogoutResp &rsp, bool sysOp = false, string ip = "");
    //快速登录
    int QuickLogin(const LoginProto::QuickLoginReq &req, LoginProto::QuickLoginResp &rsp, const map<string, string> &extraInfo);
    //
    int DeviceLogin(const LoginProto::DeviceLoginReq &req, LoginProto::DeviceLoginResp &rsp, const map<string, string> &extraInfo, const int iVer);
    //
    int DeviceUpgrade(const LoginProto::DeviceUpgradeReq &req, LoginProto::DeviceUpgradeResp &rsp, const map<string, string> &extraInfo);
    //账号注册处理
    int UserRegister2(const LoginProto::RegisterReq req, LoginProto::RegisterResp &rsp, const map<std::string, std::string> &extraInfo);
    //账号注册处理
    int UserRegister(const login::RegisterReq req, login::RegisterResp &rsp, int areaID, string ip);
    //手机号注册
    int PhoneRegister(const LoginProto::PhoneRegisterReq &req, LoginProto::PhoneRegisterResp &rsp, const map<std::string, std::string> &extraInfo);

    //登录
    int UserLogin(const LoginProto::UserLoginReq &req, LoginProto::UserLoginResp &rsp, const map<string, string> &extraInfo, const int iVer);

    //手机号码登录
    int PhoneLogin(const LoginProto::PhoneLoginReq &req, LoginProto::PhoneLoginResp &rsp, const map<string, string> &extraInfo, const int iVer);
    int TestLogin(const LoginProto::PhoneLoginReq &req, LoginProto::PhoneLoginResp &rsp, const map<string, string> &extraInfo);
    //重置手机账号密码
    int PhoneResetPassword(const LoginProto::PhoneModifyPasswordReq &req, LoginProto::PhoneModifyPasswordResp &rsp);
    //发送手机验证码
    int PhoneMsgCode(const LoginProto::SendPhoneMessageCodeReq &req, LoginProto::SendPhoneMessageCodeResp &rsp);
    //邮箱注册
    int EmailRegister(const LoginProto::EmailRegisterReq &req, LoginProto::EmailRegisterResp &rsp, const map<std::string, std::string> &extraInfo);
    //邮箱登录
    int EmailLogin(const LoginProto::UserLoginReq &req, LoginProto::UserLoginResp &rsp, const map<string, string> &extraInfo, const int iVer);
    //发送邮箱验证码
    int EmailMsgCode(const LoginProto::SendEmailMessageCodeReq &req, LoginProto::SendEmailMessageCodeResp &rsp);
    //邮箱账号重置密码
    int EmailResetPassword(const LoginProto::EmailModifyPasswordReq &req, LoginProto::EmailModifyPasswordResp &rsp);
    //
    int VerifyAuthCode(const LoginProto::VerifyAuthCodeReq &req, LoginProto::VerifyAuthCodeResp &rsp);
    //
    int RegisterUserInfo( const LoginProto::RegisterUserInfoReq &req);
    //发送网关信息
    int UserRounter(const LoginProto::UserRounterInfoReq &req, LoginProto::UserRounterInfoResp &rsp);
    //第三方登录
    int ThirdPartyLogin(const LoginProto::ThirdPartyLoginReq &req, LoginProto::ThirdPartyLoginResp &rsp, const map<string, string> &extraInfo);
    //
    int authAppleLogin(const std::string &tokenid);
    //
    long getAccountUid(const string username);
    int GetServerUpdateTime(LoginProto::GetServerUpdateTimeResp &rsp);

private:
    //产生uuid串
    string generateUUIDStr();
    //
    int httpGet(const char *url, std::string &resJson);
    //
    int httpPost(const char *url, const std::vector<std::string> &headerParams, const std::string &postParams, std::string &resJson);

    //
    int sendAuthCode(const std::string &phone, const tars::Int32 &smsCode);
    //
    int setAuthData(const std::string &phone, const std::string &smsCode);
    //
    int getAuthData(const std::string &phone, std::string &ret, time_t &time);
    //
    int delAuthData(const std::string &phone);
    //
    int addPasswordErrCount(const std::string &username);
    //
    int getPasswordErrCount(const std::string &username, int &errCount, time_t &time);
    //
    int delPasswordErrCount(const std::string &username);
    // 
    int setUserPassword(const std::string &username, const std::string &password);
    //
    string getCountryByIP(const string &ip);

public:
    //
    bool ConvertJwkToPem(const std::string &strnn, const std::string &stree, std::string &strPubKey);

  /*  template<typename F, typename... Ts>
    inline std::future<typename std::result_of<F(Ts...)>::type>
    reallyAsync(F&& f, Ts&&... params)
    {
        return std::async(std::launch::async, std::forward<f>(f), std::forward<Ts>(params)...);
    }*/

};

//singleton
typedef TC_Singleton<Processor, CreateStatic, DefaultLifetime> ProcessorSingleton;

#endif
