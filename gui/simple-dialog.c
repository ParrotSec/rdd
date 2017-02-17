/*
 * Copyright (c) 2002 - 2006, Netherlands Forensic Institute
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.

 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#include <stdio.h>
#include <stdlib.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SPLASH_DURATION	1800	/* milliseconds */

void showOutput();
void showInput();
void showSplash();
void showConfirmation();
void showImaging();
void showFinishedImaging();

typedef struct _PROGRESS {
	GtkWidget *progressbar;
	GtkWidget *copiedLabel;
	int        cancelled;
} PROGRESS;

#define WINDOW_INPUT 1
#define WINDOW_OUTPUT 2
#define WINDOW_CONFIRMATION 3
#define WINDOW_IMAGING 4
#define WINDOW_FINISHED 5

struct {
	int exitStatus;
	int window;
}exitData;

#define UNDEFINED 0
#define NEXT 1
#define BACK 2
#define FINISH 3
#define EXIT 4
#define CANCEL 4
int exitStatus;

typedef unsigned long long rdd_count_t;

static char *input_file;

static void
report_progress(rdd_count_t filesize, rdd_count_t copied, void *env)
{
	PROGRESS *p = (PROGRESS *) env;
	double frac;
	char buf[16];

	frac = ((double) copied) / ((double) filesize);
	gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(p->progressbar), frac);

	snprintf(buf, 15, "%llu", copied);
	buf[15] = '\000';
	gtk_label_set_text(GTK_LABEL(p->copiedLabel), buf);
}

static void
read_file(char *path, void *env)
{
	PROGRESS *p = (PROGRESS *) env;
	unsigned char buf[131072];
	struct stat statbuf;
	rdd_count_t filesize = 0;
	rdd_count_t copied = 0;
	int fd;
	int n;

	if (stat(path, &statbuf) < 0) {
		perror("stat");
		exit(EXIT_FAILURE);
	}
	filesize = statbuf.st_size;

	if ((fd = open(path, O_RDONLY)) < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	while (1) {
		n = read(fd, buf, sizeof buf);
		if (n == 0) {
			break;
		} else if (n < 0) {
			if (errno == EINTR) continue;

			perror("read");
			exit(EXIT_FAILURE);
		}
		copied += n;

		report_progress(filesize, copied, p);
		gtk_main_iteration_do(0);

		if (p->cancelled) {
			break;
		}
	}

	(void) close(fd);
}

static gboolean
splash_timeout(gpointer data)
{
	volatile int *timed_out = (volatile int *) data;

	*timed_out = 1;
	return FALSE;
}

static void
show_splash_screen(void)
{
	volatile int timed_out = 0;
	guint timeout_id;
	GtkWidget *winSplash;
	GladeXML *xml;

	xml = glade_xml_new("rddgui.glade", "winSplash", NULL);
	winSplash = glade_xml_get_widget(xml, "winSplash");
	glade_xml_signal_autoconnect(xml);

	timeout_id = gtk_timeout_add(SPLASH_DURATION,
			splash_timeout, (int *) &timed_out);

	while (! timed_out) {
		gtk_main_iteration_do(1);
	}

	gtk_timeout_remove(timeout_id);
	gtk_widget_hide(winSplash);

}

gboolean
bCancel_clicked(GtkObject *obj, gpointer env)
{
	PROGRESS *p = (PROGRESS *) env;

	p->cancelled = 1;
	printf("CANCEL\n");
	return TRUE;
}

static void
show_progress(GladeXML *xml)
{
	GtkWidget *copywin;
	GtkWidget *cancel;
	GtkWidget *msgDone;
	GtkWidget *msgCancelled;
	PROGRESS progress_info;
	gint result;

	progress_info.progressbar = glade_xml_get_widget(xml, "pbCopyProgress");
	progress_info.copiedLabel = glade_xml_get_widget(xml, "lblBytesCopied");
	progress_info.cancelled = 0;

	glade_xml_signal_connect_data(xml, "bCancel_clicked",
			GTK_SIGNAL_FUNC(bCancel_clicked), &progress_info);

	cancel = glade_xml_get_widget(xml, "bCancel");
	gtk_widget_set_sensitive(cancel, TRUE);

	copywin = glade_xml_get_widget(xml, "copying");
	gtk_widget_show(copywin);

	read_file(input_file, &progress_info);

	gtk_widget_set_sensitive(cancel, FALSE);

	if (progress_info.cancelled) {
		msgCancelled = glade_xml_get_widget(xml, "msgCopyCancelled");
		(void) gtk_dialog_run(GTK_DIALOG(msgCancelled));
		gtk_widget_hide(msgCancelled);
	} else {
		msgDone = glade_xml_get_widget(xml, "msgCopyDone");
		(void) gtk_dialog_run(GTK_DIALOG(msgDone));
		gtk_widget_hide(msgDone);
	}


	gtk_widget_hide(copywin);
}

gboolean Next_clicked(GtkWidget *widget, gpointer data){

	GladeXML *xml;

	g_print("Next clicked\n");

	//gtk_widget_hide(GTK_WIDGET(data));
	
	exitStatus = NEXT;
}

gboolean Advanced_clicked(GtkWidget *widget, gpointer data){

	GladeXML *xml;

	g_print("Advanced clicked\n");

	//gtk_widget_hide(GTK_WIDGET(data));
	
	exitStatus = 0;
}

gboolean Back_clicked(GtkWidget *widget, gpointer data){

	GladeXML *xml;

	g_print("Back clicked\n");

	//gtk_widget_hide(GTK_WIDGET(data));
	
	exitStatus = BACK;
}

gboolean finishClicked(GtkWidget *widget, gpointer data){

	GladeXML *xml;

	g_print("Finish clicked\n");

	gtk_widget_hide(GTK_WIDGET(data));
	
	exitStatus = FINISH;
}

gboolean cancelClicked(GtkWidget *widget, gpointer data){

	GladeXML *xml;

	g_print("Cancel clicked\n");

	gtk_widget_hide(GTK_WIDGET(data));
	
	exitStatus = CANCEL;
}

gboolean exitClicked(GtkWidget *widget, gpointer data){

	GladeXML *xml;

	g_print("Exit clicked\n");

	gtk_widget_hide(GTK_WIDGET(data));
	
	exitStatus = EXIT;
}



void
showInput(){

	GladeXML *xml;
	GtkWidget *window;
	int res;

	xml = glade_xml_new("simple-dialog.glade", "dlgInput", NULL);
	window = glade_xml_get_widget(xml, "dlgInput");

	glade_xml_signal_connect_data(xml, "on_butNext_clicked",
			GTK_SIGNAL_FUNC(Next_clicked), window);
	glade_xml_signal_connect_data(xml, "on_butBack_clicked",
			GTK_SIGNAL_FUNC(Back_clicked), window);
	glade_xml_signal_connect_data(xml, "on_butAdv_clicked",
			GTK_SIGNAL_FUNC(Advanced_clicked), window);

	do{
		res = gtk_dialog_run(GTK_DIALOG(window));
		g_print("gtk_dialog_run returned %i\n", res);
	} while (res == 30);
	
		

	
/*
	exitStatus = 0;
	while (!exitStatus)
		gtk_main_iteration();
	
	if (exitStatus == NEXT){
		g_print ("Exit status was NEXT\n");
		showOutput();
	}
*/

	/*
	else if (exitStatus == BACK){
		g_print ("Exit status was BACK\n");
	}
	*/

}

void
showOutput(){

	GladeXML *xml;
	GtkWidget *window;
	int res;

	xml = glade_xml_new("simple-dialog.glade", "dlgOutput", NULL);
	window = glade_xml_get_widget(xml, "dlgOutput");

	do{
		res = gtk_dialog_run(GTK_DIALOG(window));
		g_print("gtk_dialog_run returned %i\n", res);
	} while (res == 30);

	
	/*
	glade_xml_signal_connect_data(xml, "on_butNext_clicked",
			GTK_SIGNAL_FUNC(Next_clicked), window);
	glade_xml_signal_connect_data(xml, "on_butBack_clicked",
			GTK_SIGNAL_FUNC(Back_clicked), window);

	exitStatus = 0;
	while (!exitStatus)
		gtk_main_iteration();
	
	if (exitStatus == NEXT){
		g_print ("Exit status was NEXT\n");
		showConfirmation();
	}
	else if (exitStatus == BACK){
		g_print ("Exit status was BACK\n");
		showInput();
	}
	*/
}

void
showConfirmation(){

	GladeXML *xml;
	GtkWidget *window;
	int res;

	xml = glade_xml_new("simple-dialog.glade", "dlgConfirmation", NULL);
	window = glade_xml_get_widget(xml, "dlgConfirmation");
	
	do{
		res = gtk_dialog_run(GTK_DIALOG(window));
		g_print("gtk_dialog_run returned %i\n", res);
	} while (res == 30);

	/*
	glade_xml_signal_connect_data(xml, "on_butFinish_clicked",
			GTK_SIGNAL_FUNC(finishClicked), window);
	glade_xml_signal_connect_data(xml, "on_butBack_clicked",
			GTK_SIGNAL_FUNC(Back_clicked), window);
	

	exitStatus = 0;
	while (!exitStatus)
		gtk_main_iteration();
	
	if (exitStatus == FINISH){
		g_print ("Exit status was FINISH\n");
		showImaging();
	}
	else if (exitStatus == BACK){
		g_print ("Exit status was BACK\n");
		showOutput();
	}
	*/

}

void
showImaging(){

	GladeXML *xml;
	GtkWidget *window;
	int res;

	xml = glade_xml_new("simple-dialog.glade", "dlgImaging", NULL);
	window = glade_xml_get_widget(xml, "dlgImaging");

	do{
		res = gtk_dialog_run(GTK_DIALOG(window));
		g_print("gtk_dialog_run returned %i\n", res);
	} while (res == 30);

/*
	glade_xml_signal_connect_data(xml, "on_butCancel_clicked",
			GTK_SIGNAL_FUNC(cancelClicked), window);

	exitStatus = 0;
	while (!exitStatus)
		gtk_main_iteration();
	
	if (exitStatus == CANCEL){
		g_print ("Exit status was CANCEL\n");
		showFinishedImaging();
	}
*/
}

void
showFinishedImaging(){

	GladeXML *xml;
	GtkWidget *window;
	int res;

	xml = glade_xml_new("simple-dialog.glade", "dlgFinishedImaging", NULL);
	window = glade_xml_get_widget(xml, "dlgFinishedImaging");

	do{
		res = gtk_dialog_run(GTK_DIALOG(window));
		g_print("gtk_dialog_run returned %i\n", res);
	} while (res == 30);

/*
	glade_xml_signal_connect_data(xml, "on_butExit_clicked",
			GTK_SIGNAL_FUNC(exitClicked), window);
	glade_xml_signal_connect_data(xml, "on_butBack_clicked",
			GTK_SIGNAL_FUNC(Back_clicked), window);

	exitStatus = 0;
	while (!exitStatus)
		gtk_main_iteration();
	
	if (exitStatus == EXIT){
		g_print ("Exit status was EXIT\n");
		//will be quitting app.
	}
	else if (exitStatus == BACK){
		g_print ("Exit status was BACK\n");
		showConfirmation();
	}
*/
}

void
showSplash(){

	GladeXML *xml;
	GtkWidget *window;
	int res;

	xml = glade_xml_new("simple-dialog.glade", "dlgSplash", NULL);
	window = glade_xml_get_widget(xml, "dlgSplash");

	do{
		res = gtk_dialog_run(GTK_DIALOG(window));
		g_print("gtk_dialog_run returned %i\n", res);
	} while (res == 30);
}

void
showProfile(){

	GladeXML *xml;
	GtkWidget *window;
	int res;

	xml = glade_xml_new("simple-dialog.glade", "dlgProfile", NULL);
	window = glade_xml_get_widget(xml, "dlgProfile");

	do{
		res = gtk_dialog_run(GTK_DIALOG(window));
		g_print("gtk_dialog_run returned %i\n", res);
	} while (res == 30);
}

void
showInputAdv(){

	GladeXML *xml;
	GtkWidget *window;
	int res;

	xml = glade_xml_new("simple-dialog.glade", "dlgInputAdv", NULL);
	window = glade_xml_get_widget(xml, "dlgInputAdv");

	do{
		res = gtk_dialog_run(GTK_DIALOG(window));
		g_print("gtk_dialog_run returned %i\n", res);
	} while (res == 30);
}

void
showOutputAdv(){

	GladeXML *xml;
	GtkWidget *window;
	int res;

	xml = glade_xml_new("simple-dialog.glade", "dlgOutputAdv", NULL);
	window = glade_xml_get_widget(xml, "dlgOutputAdv");

	do{
		res = gtk_dialog_run(GTK_DIALOG(window));
		g_print("gtk_dialog_run returned %i\n", res);
	} while (res == 30);
}

void
showIntegrity(){

	GladeXML *xml;
	GtkWidget *window;
	int res;

	xml = glade_xml_new("simple-dialog.glade", "dlgIntegrity", NULL);
	window = glade_xml_get_widget(xml, "dlgIntegrity");

	do{
		res = gtk_dialog_run(GTK_DIALOG(window));
		g_print("gtk_dialog_run returned %i\n", res);
	} while (res == 30);
}

void
showIntegrityAdv(){

	GladeXML *xml;
	GtkWidget *window;
	int res;

	xml = glade_xml_new("simple-dialog.glade", "dlgIntegrityAdv", NULL);
	window = glade_xml_get_widget(xml, "dlgIntegrityAdv");

	do{
		res = gtk_dialog_run(GTK_DIALOG(window));
		g_print("gtk_dialog_run returned %i\n", res);
	} while (res == 30);
}

void
showErrorRecovery(){

	GladeXML *xml;
	GtkWidget *window;
	int res;

	xml = glade_xml_new("simple-dialog.glade", "dlgErrorRecovery", NULL);
	window = glade_xml_get_widget(xml, "dlgErrorRecovery");

	do{
		res = gtk_dialog_run(GTK_DIALOG(window));
		g_print("gtk_dialog_run returned %i\n", res);
	} while (res == 30);
}

void
showErrorRecoveryAdv(){

	GladeXML *xml;
	GtkWidget *window;
	int res;

	xml = glade_xml_new("simple-dialog.glade", "dlgErrorRecoveryAdv", NULL);
	window = glade_xml_get_widget(xml, "dlgErrorRecoveryAdv");

	do{
		res = gtk_dialog_run(GTK_DIALOG(window));
		g_print("gtk_dialog_run returned %i\n", res);
	} while (res == 30);
}

void
showStatistics(){

	GladeXML *xml;
	GtkWidget *window;
	int res;

	xml = glade_xml_new("simple-dialog.glade", "dlgStatistics", NULL);
	window = glade_xml_get_widget(xml, "dlgStatistics");

	do{
		res = gtk_dialog_run(GTK_DIALOG(window));
		g_print("gtk_dialog_run returned %i\n", res);
	} while (res == 30);
}

void
showStatisticsAdv(){

	GladeXML *xml;
	GtkWidget *window;
	int res;

	xml = glade_xml_new("simple-dialog.glade", "dlgStatisticsAdv", NULL);
	window = glade_xml_get_widget(xml, "dlgStatisticsAdv");

	do{
		res = gtk_dialog_run(GTK_DIALOG(window));
		g_print("gtk_dialog_run returned %i\n", res);
	} while (res == 30);
}




int
main(int argc, char **argv)
{
	int rc;

	input_file = argv[1];

	gtk_init(&argc, &argv);
	glade_init();

	g_print("Start\n");

	showInput();
#if 0
	showSplash();
	showProfile();
	showInputAdv();
	showOutput();
	showConfirmation();
	showImaging();
	showFinishedImaging();

	showOutputAdv();
	showIntegrity();
	showIntegrityAdv();
#endif
	
	showErrorRecovery();
	showErrorRecoveryAdv();
	showStatistics();
	showStatisticsAdv();

	//xml = glade_xml_new("copying/copying.glade", NULL, NULL);
	//show_progress(xml);

	g_print("End\n");
	return 0;
}
