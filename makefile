
#-----------------------------------------------------------------------

APP           := XGame
TARGET        := LoginServer
CONFIG        := 
STRIP_FLAG    := N
TARS2CPP_FLAG := 
CFLAGS        += -lm
CXXFLAGS      += -lm

INCLUDE   += -I/usr/local/cpp_modules/wbl/include
LIB       += -L/usr/local/cpp_modules/wbl/lib -lwbl

INCLUDE   += -I/usr/local/cpp_modules/json-0.5/include
LIB       += -L/usr/local/cpp_modules/json-0.5/lib -ljson

INCLUDE   += -I/usr/local/cpp_modules/curl/include
LIB       += -L/usr/local/cpp_modules/curl/lib -lcurl

INCLUDE   += -I/usr/local/cpp_modules/pcre/include
LIB       += -L/usr/local/cpp_modules/pcre/lib -lpcre

INCLUDE   += -I/usr/local/cpp_modules/protobuf/include
LIB       += -L/usr/local/cpp_modules/protobuf/lib -lprotobuf

INCLUDE   += -I/usr/local/cpp_modules/uuid/include
LIB       += -L/usr/local/cpp_modules/uuid/lib -luuid

INCLUDE   += -I/usr/local/cpp_modules/maxminddb/include
LIB       += -L/usr/local/cpp_modules/maxminddb/lib -lmaxminddb

INCLUDE   += -I/usr/local/cpp_modules/jwt/include
LIB       += -L/usr/local/cpp_modules/jwt/ -lssl -lcrypto -lz

#-----------------------------------------------------------------------
include /home/tarsproto/XGame/Comm/Comm.mk
include /home/tarsproto/XGame/util/util.mk
include /home/tarsproto/XGame/protocols/protocols.mk
include /home/tarsproto/XGame/ConfigServer/ConfigServer.mk
include /home/tarsproto/XGame/HallServer/HallServer.mk
include /home/tarsproto/XGame/GlobalServer/GlobalServer.mk
include /home/tarsproto/XGame/PushServer/PushServer.mk
include /home/tarsproto/XGame/RouterServer/RouterServer.mk
include /home/tarsproto/XGame/DBAgentServer/DBAgentServer.mk
include /home/tarsproto/XGame/GameRecordServer/GameRecordServer.mk
include /home/tarsproto/XGame/Log2DBServer/Log2DBServer.mk
include /usr/local/tars/cpp/makefile/makefile.tars
#-----------------------------------------------------------------------

jf: $(TARGET)
	cp -f $(TARGET) /usr/local/app/tars/tarsnode/data/JFGame.LoginServer/bin/

daqi:
	cp -f $(TARGET) /usr/local/app/tars/tarsnode/data/DaqiGame.LoginServer/bin/

xgame:
	cp -f $(TARGET) /usr/local/app/tars/tarsnode/data/XGame.LoginServer/bin/

100:
	sshpass -p 'awzs2022' scp ./LoginServer root@10.10.10.100:/home/yuj/server/loginserver
