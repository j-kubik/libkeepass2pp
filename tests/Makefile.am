check_PROGRAMS = pipeline compositekey cryptorandom

pipeline_SOURCES = pipeline.test.cpp
pipeline_CPPFLAGS = $(libxml2_CFLAGS) $(openssl_CFLAGS) $(zlib_CFLAGS) -I../include
pipeline_LDFLAGS= -pthread -L../src -lkeepass2pp $(libxml2_LIBS) $(openssl_LIBS) $(zlib_LIBS)

compositekey_SOURCES = compositekey.test.cpp
compositekey_CPPFLAGS = -I../include
compositekey_LDFLAGS= -pthread -L../src -lkeepass2pp

cryptorandom_SOURCES = cryptorandom.test.cpp
cryptorandom_CPPFLAGS = -I../include
cryptorandom_LDFLAGS= -pthread -L../src -lkeepass2pp

TESTS = pipeline.sh compositekey.sh cryptorandom.sh

EXTRA_DIST = TestDatabase.kdbx  TestDatabase.key  TestDatabase.pass
EXTRA_DIST += pipeline.sh pipeline.input
EXTRA_DIST += compositekey.sh
