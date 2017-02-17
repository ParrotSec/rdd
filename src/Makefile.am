## Process this file with automake to produce Makefile.in

if GCC_COMPILER
AM_CFLAGS = -pedantic -Wno-long-long -g3 -Wall -Wmissing-prototypes
else
AM_CFLAGS = 
endif
AM_LDFLAGS = -dynamic

bin_PROGRAMS = rdd-copy rdd-verify

noinst_LIBRARIES=librdd.a

librdd_a_SOURCES = rdd.h rsysint.h \
		strerror.c \
		console.c error.h error.c \
		rdd_internals.c rdd_internals.h \
		commandline.c commandline.h \
		md5.c md5.h \
		sha1.c sha1.h \
		outfile.h outfile.c \
		numparser.h numparser.c \
		alignedbuf.h alignedbuf.c \
		writer.h writer.c \
		zlibwriter.c fdwriter.c filewriter.c \
		tcpwriter.c safewriter.c partwriter.c \
		reader.h reader.c \
		fdreader.c filereader.c atomicreader.c \
		zlibreader.c faultyreader.c rawreader.c \
		alignedreader.c \
		filterset.h filterset.c \
		filter.h filter.c \
		md5streamfilter.c sha1streamfilter.c writestreamfilter.c \
		statsblockfilter.c md5blockfilter.c checksumblockfilter.c \
		verifyblockfilter.c \
		copier.h copier.c robustcopier.c simplecopier.c \
		progress.c progress.h \
		msgprinter.h msgprinter.c stdioprinter.c fileprinter.c \
		bcastprinter.c logprinter.c \
		netio.c netio.h

rdd_copy_SOURCES = rddcopy.c
rdd_copy_LDADD = librdd.a

rdd_verify_SOURCES = rddverify.c
rdd_verify_LDADD = librdd.a

man_MANS = rdd-copy.1 rdd-verify.1

install-exec-local:
	$(INSTALL) $(srcdir)/rddi.py $(bindir)/rddi
	$(INSTALL) $(srcdir)/plot-entropy.py $(bindir)/plot-entropy
	$(INSTALL) $(srcdir)/plot-md5.py $(bindir)/plot-md5

uninstall-local:
	rm -f $(bindir)/rddi
	rm -f $(bindir)/plot-entropy
	rm -f $(bindir)/plot-md5

EXTRA_DIST = $(man_MANS) rddi.py plot-entropy.py plot-md5.py
