check_PROGRAMS = pipeline

pipeline_SOURCES = pipeline.test.cpp

pipeline_CPPFLAGS = $(libxml2_CFLAGS) $(openssl_CFLAGS) $(zlib_CFLAGS) -I../include
pipeline_LDFLAGS= -pthread -L../src -lkeepass2pp $(libxml2_LIBS) $(openssl_LIBS) $(zlib_LIBS)

TESTS = pipeline.sh

EXTRA_DIST = pipeline.sh pipeline.input TestDatabase.kdbx  TestDatabase.key  TestDatabase.pass