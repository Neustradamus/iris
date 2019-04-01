INCLUDEPATH *= $$PWD/../..
DEPENDPATH *= $$PWD/../..

HEADERS += \
    $$PWD/plainmessage.h \
    $$PWD/digestmd5proplist.h \
    $$PWD/digestmd5response.h \
    $$PWD/scramshamessage.h \
    $$PWD/scramsharesponse.h \
    $$PWD/scramshasignature.cpp

SOURCES += \
    $$PWD/plainmessage.cpp \
    $$PWD/digestmd5proplist.cpp \
    $$PWD/digestmd5response.cpp \
    $$PWD/scramshamessage.cpp \
    $$PWD/scramsharesponse.cpp \
    $$PWD/scramshasignature.cpp
