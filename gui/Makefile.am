## Process this file with automake to produce Makefile.in

AM_CFLAGS = $(GTK_CFLAGS) $(LIBGLADE_CFLAGS)

if GCC_COMPILER
AM_CFLAGS += -W -Wall -Wmissing-prototypes
endif
AM_CPPFLAGS = -DPKGDATADIR=$(pkgdatadir) -I../src -DPLOT_ENTROPY

# Unfortunately, I have not found m4 macros for libglade-2.0,
# so I had to add these paths manually
AM_LDFLAGS = $(GTK_LDFLAGS) $(LIBGLADE_LIBS)
# AM_LDFLAGS += -Wl,--export-dynamic
# AM_LDFLAGS += -lglade-2.0 -lgtk-x11-2.0 -lxml2 -lz -lgdk-x11-2.0 \
		# -latk-1.0 -lgdk_pixbuf-2.0 -lm -lpangoxft-1.0 \
		# -lpangox-1.0 -lpango-1.0 -lgobject-2.0 -lgmodule-2.0 \
		# -ldl -lglib-2.0  

bin_PROGRAMS = rdd-gui

noinst_PROGRAMS = rdd-main

rdd_gui_SOURCES = rddgui.c \
		  wizwin.c rddgui.h init.c \
		  inputwizwin.c inputadvwizwin.c outputwizwin.c \
		  confirmationwizwin.c networkwizwin.c imageorverifywizwin.c \
		  integritywizwin.c recoverywizwin.c statswizwin.c \
		  serverwizwin.c \
		  finishedwin.c \
		  util.c splash.c help.c \
		  guiprinter.c guilogprinter.c \
		  outputfile.c plotentropyblockfilter.c
rdd_gui_LDADD = ../src/librdd.a
rdd_gui_LDFLAGS = $(AM_LDFLAGS)

rdd_main_SOURCES = winmain.c \
		  wizwin.c rddgui.h init.c \
		  inputwizwin.c inputadvwizwin.c outputwizwin.c \
		  confirmationwizwin.c networkwizwin.c imageorverifywizwin.c \
		  integritywizwin.c recoverywizwin.c statswizwin.c \
		  finishedwin.c \
		  util.c splash.c help.c \
		  guiprinter.c \
		  outputfile.c
rdd_main_LDADD = ../src/librdd.a
rdd_main_LDFLAGS = $(AM_LDFLAGS)

dist_pkgdata_DATA = rddgui.glade minjuslogo.png minjuslogo-200.png \
		    html/rddgui.html html/helpstyle.css
