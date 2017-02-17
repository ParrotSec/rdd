## Process this file with automake to produce Makefile.in

if GCC_COMPILER
AM_CFLAGS = -W -Wall -Wmissing-prototypes
else
AM_CFLAGS = 
endif
AM_CPPFLAGS = -I../src
AM_LDFLAGS = -static

TESTS=	tbuildtestfile
TESTS+=	test001
TESTS+=	test002
TESTS+=	test003
TESTS+=	test004
TESTS+=	test005
TESTS+=	test006
TESTS+=	tnumparser
TESTS+=	talignedbuf
TESTS+=	tnewwriter
TESTS+=	tsha1filter
TESTS+=	trunmd5blockfilter.sh
TESTS+=	ttcpwriter.sh
TESTS+=	tmsgprinter.sh

noinst_PROGRAMS = \
		tbuildtestfile tcompress tfile tfiledesc tsafe tpart \
		tnumparser talignedbuf \
		tnewwriter tsha1filter treader tmd5blockfilter ttcpwriter \
		tmsgprinter

WRITERCORE = twriter.c rddtest.c rddtest.h

tcompress_SOURCES = $(WRITERCORE) tcompress.c
tcompress_LDADD = ../src/librdd.a

tfile_SOURCES = $(WRITERCORE) tfile.c
tfile_LDADD = ../src/librdd.a

tfiledesc_SOURCES = $(WRITERCORE) tfiledesc.c
tfiledesc_LDADD = ../src/librdd.a

tsafe_SOURCES = $(WRITERCORE) tsafe.c
tsafe_LDADD = ../src/librdd.a

tpart_SOURCES = $(WRITERCORE) tpart.c
tpart_LDADD = ../src/librdd.a

tnumparser_SOURCES = tnumparser.c
tnumparser_LDADD = ../src/librdd.a

talignedbuf_SOURCES = talignedbuf.c
talignedbuf_LDADD = ../src/librdd.a

tnewwriter_SOURCES = tnewwriter.c
tnewwriter_LDADD = ../src/librdd.a

tsha1filter_SOURCES = tsha1filter.c
tsha1filter_LDADD = ../src/librdd.a

treader_SOURCES = treader.c
treader_LDADD = ../src/librdd.a

tbuildtestfile_SOURCES = tbuildtestfile.c
tbuildtestfile_LDADD = ../src/librdd.a

tmd5blockfilter_SOURCES = tmd5blockfilter.c
tmd5blockfilter_LDADD = ../src/librdd.a

ttcpwriter_SOURCES = ttcpwriter.c
ttcpwriter_LDADD = ../src/librdd.a

tmsgprinter_SOURCES = tmsgprinter.c
tmsgprinter_LDADD = ../src/librdd.a
