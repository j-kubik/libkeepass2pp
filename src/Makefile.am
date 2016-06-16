lib_LTLIBRARIES = libkeepass2pp.la

libkeepass2pp_la_SOURCES = compositekey.cpp \
                           cryptorandom.cpp \
                           database.cpp \
                           database_file.cpp \
                           wrappers.cpp \
                           links.cpp \
                           pipeline.cpp \
                           util.cpp

libkeepass2pp_la_CPPFLAGS = $(libxml2_CFLAGS) $(openssl_CFLAGS) $(zlib_CFLAGS) -I../include
libkeepass2pp_la_LDFLAGS= -pthread $(libxml2_LIBS) $(openssl_LIBS) $(zlib_LIBS) -version-info @VERSION@

#if IS_WIN32
#libkeepass2pp_la_SOURCES += platform_w32.cpp
#else !IS_WIN32
libkeepass2pp_la_CPPFLAGS += $(libuuid_CFLAGS)
libkeepass2pp_la_LDFLAGS += $(libuuid_LIBS)
libkeepass2pp_la_SOURCES += platform_other.cpp
#endif !IS_WIN32



