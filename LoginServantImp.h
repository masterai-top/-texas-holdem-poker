#ifndef _LoginServantImp_H_
#define _LoginServantImp_H_

#include "servant/Application.h"
#include "LoginServant.h"
#include "XGameComm.pb.h"
#include "CommonCode.pb.h"
#include "CommonStruct.pb.h"
#include "login.pb.h"
#include "XGameComm.pb.h"
#include "XGameHttp.pb.h"
#include "CommonCode.pb.h"
#include "CommonStruct.pb.h"

//
using namespace login;

/**
 *登录服务逻辑处理接口
 *
 */
class LoginServantImp : public login::LoginServant
{
public:
    /**
     *
     */
    virtual ~LoginServantImp() {}

    /**
     *
     */
    virtual void initialize();

    /**
     *
     */
    virtual void destroy();

public:
    //http请求处理接口
    virtual tars::Int32 doRequest(const vector<tars::Char> &reqBuf, const map<std::string, std::string> &extraInfo,
                                  vector<tars::Char> &rspBuf, tars::TarsCurrentPtr current);

    //tcp请求处理接口
    virtual tars::Int32 onRequest(tars::Int64 lUin, const std::string &sMsgPack, const std::string &sCurServrantAddr,
                                  const JFGame::TClientParam &stClientParam, const JFGame::UserBaseInfoExt &stUserBaseInfo, tars::TarsCurrentPtr current);

public:
    //校验token
    virtual tars::Int32 checkLoginToken(const login::CheckLoginTokenReq &req, login::CheckLoginTokenResp &resp, tars::TarsCurrentPtr current);
    //账号注册
    virtual tars::Int32 Register(const login::RegisterReq &req, login::RegisterResp &resp, tars::TarsCurrentPtr current);
    //账号退出
    virtual tars::Int32 Logout(const login::UserLogoutReq &req, login::UserLogoutResp &resp, tars::TarsCurrentPtr current);
    //用户状态
    virtual tars::Int32 UserState(const long uid, const int state, tars::TarsCurrentPtr current);

public:
    //账号登出
    int onUserLogout(const XGameComm::TPackage &pkg, const LoginProto::LogoutReq &logoutReq, const std::string &sCurServrantAddr);
    //发送手机验证码
    virtual tars::Int32 onSendPhoneMsgCode(const XGameComm::TPackage pkg, const LoginProto::SendPhoneMessageCodeReq &req, const std::string &sCurServrantAddr,
                                          const JFGame::TClientParam &stClientParam, const JFGame::UserBaseInfoExt &stUserBaseInfo);
    tars::Int32 onSendEmailMsgCode(const XGameComm::TPackage pkg, const LoginProto::SendEmailMessageCodeReq &req, const std::string &sCurServrantAddr,
        const JFGame::TClientParam &stClientParam, const JFGame::UserBaseInfoExt &stUserBaseInfo);
private:
    //更新用户登录(或上线)和登出(或离线)时间
    int updateUserLoginTime(tars::Int64 uid, int iState);

private:
    //发送消息到客户端
    template <typename T>
    int toClientPb(const XGameComm::TPackage &tPackage, const std::string &sCurServrantAddr, XGameProto::ActionName actionName, const T &t);

private:
    //产生uuid串
    string generateUUIDStr();
};
/////////////////////////////////////////////////////
#endif
