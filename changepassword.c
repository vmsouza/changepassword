/* changepassword.c
 *
 * ChangePassword modifies the passwords of passwd, Samba, and Squid through
 * the Web. All passwords are syncronized and changed in real time through
 * browsers like Mozilla, Netscape, IE, Opera, and others.
 *
 * copyright (c) 2002 by Vinicius Souza <vinicius@opentech.inf.br>
 * initial release 0.1 on 2002-06-05 by Vinicius Souza
 * release 0.2 on 2002-06-06 by Vinicius Souza
 * release 0.3 on 2002-06-10 by Vinicius Souza
 * release 0.4 on 2002-06-17 by Vinicius Souza
 * release 0.5 on 2002-09-09 by Vinicius Souza
 * release 0.6 on 2003-04-24 by Vinicius Souza
 * release 0.6-1 on 2003-04-30 by Vinicius Souza
 * release 0.7 on 2003-07-30 by Vinicius Souza
 * release 0.8 on 2004-09-01 by Vinicius Souza
 * release 0.9 on 2005-01-08 by Vinicius Souza
 *
 * Parts of the program are taken from:
 *    frgpasswd.c		by Knut Grahlmann <Knut.Grahlmann@bigfoot.com>
 *    chetcpasswd.c		by Pedro L. Orso <orso@onda.com.br>
 *    setpwnam.c		by Salvatore Valente <svalente@mit.edu>
 *    passwd.c		  	by Peter Orbaek <poe@daimi.aau.dk>
 *    smbencrypt package	by Gerald Carter <jerry@samba.org>
 *
 * !!! See README before compile !!!
 *
 * -----------------------------------------------------------------------
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 * -----------------------------------------------------------------------
*/

#define _XOPEN_SOURCE
#include "defs.h"

main(int argc, char *argv[]) {

#define false 0
#define true 1
#define bin_to_ascii(c) ((c)>=38?((c)-38+'a'):(c)>=12?((c)-12+'A'):(c)+'.')

typedef int boolean;

int form_error;
int buflen = 256;

char delimiter[] = ":";

char form_user[20];
char form_pw[20];
char form_newpw1[20];
char form_newpw2[20];
char form_pwtmp[20];
char buf[MAXLEN];
char *linebuf = malloc(buflen);

int contlen;
int namelen;

boolean found;

char command[255];
char *dummy;
char InputBuffer[MAXLEN];
char *pContentLength;
        
int ContentLength;
int i;
int x;
int y;

// show html header
htmlheader();

// first time, show form
if (strcmp((char *)getenv("REQUEST_METHOD"),"GET") == 0) {
	if (SMBPASSWD!="no" && SQUIDPASSWD!="no") {
		x=0;
		if (squid_file=fopen(SQUIDPASSWD,"r-"))
			fclose(squid_file);
		else
			x=2;
		if (smb_file=fopen(SMBPASSWD,"r-"))
			fclose(smb_file);
		else
			x=1;
		if (x > 0) {
			if (x==1) printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br><br>%s<br></font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg25,msg15);
			if (x==2) printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br><br>%s<br></font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg27,msg15);
			exit_prg(1);
		} else {
			showform();
			exit_prg(0);
		}
	} else {
		// don't use smbpasswd password file
		// don't use squid password file
		showform();
		exit_prg(0);
	}
} 

// change password request by user

pContentLength = (char *)getenv("CONTENT_LENGTH");

if (pContentLength != NULL)
	ContentLength = atoi(pContentLength);
else
	ContentLength = 0;

if (ContentLength > sizeof(InputBuffer)-1)
	ContentLength = sizeof(InputBuffer)-1;

i = 0;

while (i < ContentLength) {
	x = fgetc(stdin);
	if (x==EOF) break;
	InputBuffer[i++] = x;
}

InputBuffer[i] = '\0';
ContentLength = i;

// get form fields
getword(form_user,InputBuffer,'=');
getword(form_user,InputBuffer,'&');
getword(form_pw,InputBuffer,'=');
getword(form_pw,InputBuffer,'&');
getword(form_newpw1,InputBuffer,'=');
getword(form_newpw1,InputBuffer,'&');
getword(form_newpw2,InputBuffer,'=');
getword(form_newpw2,InputBuffer,'&');
form_error=0;

// convert characters URL Encoded to real chars
// example: replace %3D by =
// see bug file for information
fixpwd(form_user);
fixpwd(form_pw);
fixpwd(form_newpw1);
fixpwd(form_newpw2);

// form_user is blank?
if (strlen(form_user) == 0) {
	printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg07,msg08);
	exit_prg(1);
}

// user is allowed?
if (strstr(denyusers,form_user)) {
	printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg26,msg08);
	exit_prg(1);
}

// form_newpw1 and form_newpw2 are equals?
if (strcmp(form_newpw1,form_newpw2) != 0)
	form_error=1;

// form_newpw2 is blank?
if (strlen(form_newpw2)==0)
	form_error=3;

// form_newpw1 is blank?
if (strlen(form_newpw1)==0)
	form_error=2;

// user have a system account?
if ((sd_list=getspnam(form_user)) == 0 ) {
	printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg09,msg08);
	exit_prg(1);
}

// old password is correct?
if (strcmp(crypt(form_pw,sd_list->sp_pwdp),sd_list->sp_pwdp))
	form_error=4;

// all ok! check for password minimum lenght
if (form_error==0)
	form_error=check_passwd(form_newpw1);

// display error messages
switch(form_error) {
	case 1:
		printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg10,msg08);
		exit_prg(1);
	case 2:
		printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg11,msg08);
		exit_prg(1);
	case 3:
		printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg11,msg08);
		exit_prg(1);
	case 4:
		printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg12,msg08);
		clean_up(1);
	case 5:
		printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg13,msg08);
		exit_prg(1);
}

// generate salt
time(&tm); tm ^= getpid();
salt[0] = bin_to_ascii(tm & 0x3f);
salt[1] = bin_to_ascii((tm >> 6) & 0x3f);

// create a temporary file for shadow
if ((mkstemp(TMPFILE))<0) {
	printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br>%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg14,msg15,msg08);
	clean_up(1);
}

// crypt new password with MD5 hash
sd_list->sp_pwdp=crypt(form_newpw1,"$1$");

// minimun number of days between changes
sd_list->sp_min=PWD_MIN_DAYS;

// maximum number of days between changes
sd_list->sp_max=PWD_MAX_DAYS;

// the date of last change
sd_list->sp_lstchg=(tm/86400);

// open for read shadow file
sd_file=fopen(SHADOW_FILE,"r-");

// open for write temporary file
tmp_file=fopen(TMPFILE,"w+");

// chmod temporary file
chmod(TMPFILE,0600);

// get username length
namelen=strlen(sd_list->sp_namp);

// search for userline in passwd
found=false;
while (fgets(linebuf, buflen, sd_file) != NULL) {
	contlen = strlen(linebuf);
	while (linebuf[contlen-1] != '\n' && !feof(sd_file)) {
		buflen *= 2;
		linebuf = realloc(linebuf, buflen);
		if (linebuf == NULL) clean_up;
		if (fgets(&linebuf[contlen], buflen/2, sd_file) == NULL) break;
		contlen = strlen(linebuf);
	}
	if (!found && linebuf[namelen] == ':' && !strncmp(linebuf, sd_list->sp_namp, namelen)) {
		// write to temporary file new password for user
		setspent();
		putspent(sd_list,tmp_file);
		endspent();
	 	found = true;
	    	continue;
	}
	// write to temporary file others users
	fputs(linebuf, tmp_file);
}

// close passwd file
fclose(sd_file);

// close temporary file
fclose(tmp_file);

// lock shadow file
if (lckpwdf()<0) {
	printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg16,msg08);
	clean_up(1);
}

// rename temporary file to shadow file
if (rename(TMPFILE,SHADOW_FILE)<0) {
	printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg17,msg08);
	unlink(TMPFILE);
	clean_up(1);
}

// change user shadow file to root
if (chown(SHADOW_FILE,0,0)<0) {
	printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br>%s<br><br>%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg18,msg15,msg19,msg08);
	clean_up(1);
}

// change shadow file permissions
if (chmod(SHADOW_FILE,0640)<0) {
	printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br>%s<br><br>%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg20,msg15,msg19,msg08);
	clean_up(1);
}

// unlock shadow file
ulckpwdf();

// password in shadow file changed!
printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br></font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg21);

// change samba password
if (SMBPASSWD!="no")
	changesmbpass(form_user, form_newpw1, buflen);

// change squid password
if (SQUIDPASSWD!="no")
	changesquidpass(form_user, form_newpw1, buflen);

printf("<br><font face=\"%s\" color=\"%s\" size=\"%i\">%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg24);
clean_up(0);
exit_prg(0);
}

// function: check for min password length
int check_passwd(char *pwdstr) {
	if (strlen(pwdstr) < minpwdlen) {
	   return 5;
        }
	return 0;
}

// function: clean sd_list and se_list structure
void clean_up(int quit) {
	sd_list->sp_namp="";
        sd_list->sp_pwdp="";
        sd_list->sp_lstchg=0;
        sd_list->sp_min=0;
        sd_list->sp_max=0;
        sd_list->sp_warn=0;
        sd_list->sp_inact=0;
        sd_list->sp_expire=0;
        sd_list->sp_flag=0;
        if (quit > 1) {
		se_list->pw_name="";
		se_list->pw_passwd="";
		se_list->pw_uid=0;
		se_list->pw_gid=0;
		se_list->pw_gecos="";
		se_list->pw_dir="";
		se_list->pw_shell="";
	}
	if (quit > 0)
		exit_prg(1);
}

// function: get words from a string delimited by "stop" 
void getword(char *word, char *line, char stop) {
	int x = 0,y;
	for (x=0;((line[x]) && (line[x] != stop));x++)
		word[x] = line[x];
	word[x] = '\0';
	if (line[x]) ++x;
	y=0;
	while((line[y++] = line[x++]));
}

// function: show html header
void htmlheader() {
	printf("Content-type: text/html\n\n");
	puts("\n");
	printf("<html>\n<head>\n<title>%s</title>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\">\n</head>\n<body bgcolor=\"%s\" text=\"%s\" link=\"%s\" vlink=\"%s\" alink=\"%s\">\n",msg01,charset,BGCOLOR,FGCOLOR,LKCOLOR,LKCOLOR,LKCOLOR);
	if (LOGO!="none")
		printf("<center><img src=\"/%s\"><br><br></center>",LOGO);
	else
		printf("<br>");
	printf("<center>");
}

// function: exit program
void exit_prg(int quit) {
	printf("</center><br><hr width=\"90%\"><center><font face=\"%s\" size=\"%i\"><a href=\"%s\" target=\"_BLANK\">%s-%s</a></center>",FONTFACE,FONTSIZE,URL,PGM,VERSION);
	printf("\n</body></html>");
	exit(quit);    
}

// function: show formatted msg
void msg(char *msg) {
	printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg);
}

// function: show form in webpage
void showform() {
	printf("<form method=post action=\"changepassword.cgi\">");
	printf("<table border=0 cellspacing=2 cellpadding=2><tr bgcolor=\"%s\"><td>",BOXBOCOLOR);
	printf("<table border=0 cellspacing=0 cellpadding=2>");
	printf("<tr bgcolor=\"%s\"><td colspan=2 align=\"center\"><font color=\"%s\" face=\"%s\" size=\"%i\"><b>%s</b></font></td></td></tr>",BOXBGCOLOR,BOXFGCOLOR,FONTFACE,FONTSIZE,msg01,msg02);
	printf("<tr bgcolor=\"%s\"><td align=\"right\"><font color=\"%s\" face=\"%s\" size=\"%i\">%s: </font></td><td><input type=text name=form_user size=20 maxlength=20></td></tr>",BOXBGCOLOR,BOXFGCOLOR,FONTFACE,FONTSIZE,msg02);
	printf("<tr bgcolor=\"%s\"><td align=\"right\"><font color=\"%s\" face=\"%s\" size=\"%i\">%s: </font></td><td><input type=password name=form_pw size=20 maxlength=%i></td></tr>",BOXBGCOLOR,BOXFGCOLOR,FONTFACE,FONTSIZE,msg03,maxpwdlen);
	printf("<tr bgcolor=\"%s\"><td align=\"right\"><font color=\"%s\" face=\"%s\" size=\"%i\">%s: </font></td><td><input type=password name=form_newpw1 size=20 maxlength=%i>\n</td></tr>",BOXBGCOLOR,BOXFGCOLOR,FONTFACE,FONTSIZE,msg04,maxpwdlen);
	printf("<tr bgcolor=\"%s\"><td align=\"right\"><font color=\"%s\" face=\"%s\" size=\"%i\">%s: </font></td><td><input type=password name=form_newpw2 size=20 maxlength=%i>\n</td></tr>",BOXBGCOLOR,BOXFGCOLOR,FONTFACE,FONTSIZE,msg05,maxpwdlen);
	printf("<tr bgcolor=\"%s\"><td colspan=2 align=\"center\"><input type=submit name=submit value=\"%s\"></td></tr></table>",BOXBGCOLOR,msg06);
	printf("</td></tr></table>");
	printf("</form>");
}

// function: change samba password
void changesmbpass(char *form_user, char *form_newpw1, int buflen) {

typedef int boolean;

char smbuser[256];
char smbuid[256];
char smblanman[256];
char smbnt[256];
char smbperms[256];
char smbltc[256];

int contlen;
int namelen;
int ltc;

char *smbbuf = malloc(buflen);

boolean found;

// get passwd structure for user
se_list=getpwnam(form_user);

// get username length
found=false;
namelen=strlen(sd_list->sp_namp);

// open smb temporary file
if ((mkstemp(TMPSMBFILE))<0) {
	printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br>%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg14,msg15,msg08);
	clean_up(1);
}

// open smbpasswd file for read
if ((smb_file=fopen(SMBPASSWD,"r-"))==NULL) {
	printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br><br>%s<br></font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg25,msg15);
        exit_prg(1);
} else {
	// open smb temporary for write
	smbtmp_file=fopen(TMPSMBFILE,"w+");
	// change smb temporary file permissions
	chmod(TMPSMBFILE,0600);
	// search for user in smbpasswd file
	while (fgets(smbbuf, buflen, smb_file) != NULL) {
		contlen = strlen(smbbuf);
		getword(smbuser,smbbuf,':');
		getword(smbuid,smbbuf,':');
		getword(smblanman,smbbuf,':');
		getword(smbnt,smbbuf,':');
		getword(smbperms,smbbuf,':');
		getword(smbltc,smbbuf,':');
		strcpy(smbbuf,smbuser);
		strcat(smbbuf,":");
		strcat(smbbuf,smbuid);
		strcat(smbbuf,":");
		strcat(smbbuf,smblanman);
		strcat(smbbuf,":");
		strcat(smbbuf,smbnt);
		strcat(smbbuf,":");
		strcat(smbbuf,smbperms);
		strcat(smbbuf,":");
		strcat(smbbuf,smbltc);
		strcat(smbbuf,":\n");
		while (smbbuf[contlen-1] != '\n' && !feof(smb_file)) {
			buflen *= 2;
			smbbuf = realloc(smbbuf, buflen);
			if (smbbuf == NULL) clean_up;
			if (fgets(&smbbuf[contlen], buflen/2, smb_file) == NULL) break;
			contlen = strlen(smbbuf);
		}
		if (!found && smbbuf[namelen] == ':' && !strncmp(smbbuf, form_user, namelen)) {
			// encrypt password in smb format
			smbencrypt(form_newpw1); 
			// generate smbpasswd line format
			strcpy(command,smbuser);
			strcat(command,":");
			strcat(command,smbuid);
			strcat(command,":");
			strcat(command,smbencrypted);
			strcat(command,":");
			strcat(command,smbperms);
			strcat(command,":");
			//convert int to hex string
			ltc=tm*24*60*60;
			sprintf(unixdate, "%08X", ltc);
			strcpy(smbltc,"LCT-");
			strcat(smbltc,unixdate);
			strcat(command,smbltc);
			strcat(command,":\n");
			// write new password for to temporary file
			fputs(command, smbtmp_file);
		 	found = true;
		    	continue;
		}
		// write other users password to temporary file
		fputs(smbbuf, smbtmp_file);
	}
	// close smb temporary file
	fclose(smbtmp_file);
	// close smbpasswd file
	fclose(smb_file);
}

// open smb temporary file for read
smbtmp_file=fopen(TMPSMBFILE,"r");

// open smbpasswd file for write
smb_file=fopen(SMBPASSWD,"w");

// lock smbpasswd file
flockfile(smb_file);

// write passwords from smb temporary file to smbpasswd file
while (fgets(smbbuf, MAXLEN, smbtmp_file) != NULL)
	fputs(smbbuf,smb_file);

// unlock smbpasswd file
funlockfile(smb_file);

// close smb temporary file
fclose(smbtmp_file);

// close smbpasswd file
fclose(smb_file);

// delete smb temporary file
unlink(TMPSMBFILE);

// change user and group for smbpasswd file
if (chown(SMBPASSWD,0,0)<0) {
	printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br>%s<br><br>%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg18,msg15,msg19,msg08);
	clean_up(1);
}

// change permissions for smbpasswd file
if (chmod(SMBPASSWD,0644)<0) {
	printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br>%s<br><br>%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg20,msg15,msg19,msg08);
	clean_up(1);
}

// password in smbpasswd file changed!
printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br></font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg23);
}

// function: change squid password
void changesquidpass(char *form_user, char *form_newpw1, int buflen) {

typedef int boolean;

char squiduser[256];
char *squidpass;

int contlen;
int namelen;
int ltc;

char *squidbuf = malloc(buflen);

boolean found;

// get username length
found=false;
namelen=strlen(form_user);

// generate salt
time(&tm); tm ^= getpid();
salt[0] = bin_to_ascii(tm & 0x3f);
salt[1] = bin_to_ascii((tm >> 6) & 0x3f);

// open squid temporary file
if ((mkstemp(TMPSQUIDFILE))<0) {
	printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br>%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg14,msg15,msg08);
	clean_up(1);
}

// open squid password file for read
if ((squid_file=fopen(SQUIDPASSWD,"r-"))==NULL) {
	printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br><br>%s<br></font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg27,msg15);
        exit_prg(1);
} else {
	// open squid temporary for write
	squidtmp_file=fopen(TMPSQUIDFILE,"w+");
	// change squid temporary file permissions
	chmod(TMPSQUIDFILE,0600);
	// search for user in squid password file
	while (fgets(squidbuf, buflen, squid_file) != NULL) {
		contlen = strlen(squidbuf);
		while (squidbuf[contlen-1] != '\n' && !feof(squid_file)) {
			buflen *= 2;
			squidbuf = realloc(squidbuf, buflen);
			if (squidbuf == NULL) clean_up;
			if (fgets(&squidbuf[contlen], buflen/2, squid_file) == NULL) break;
			contlen = strlen(squidbuf);
		}
		if (!found && squidbuf[namelen] == ':' && !strncmp(squidbuf, form_user, namelen)) {
			// encrypt password in crypt/des format
			squidpass=crypt(form_newpw1,salt);
			// generate squid password line format
			strcpy(command,form_user);
			strcat(command,":");
			strcat(command,squidpass);
			strcat(command,"\n");
			// write new password for to temporary file
			fputs(command, squidtmp_file);
		 	found = true;
		    	continue;
		}
		// write other users password to temporary file
		fputs(squidbuf, squidtmp_file);
	}
	// close squid temporary file
	fclose(squidtmp_file);
	// close squid passwd file
	fclose(squid_file);
}

// open squid temporary file for read
squidtmp_file=fopen(TMPSQUIDFILE,"r");

// open squid passwd file for write
squid_file=fopen(SQUIDPASSWD,"w");

// lock squid passwd file
flockfile(squid_file);

// write passwords from squid temporary file to squid passwd file
while (fgets(squidbuf, MAXLEN, squidtmp_file) != NULL)
	fputs(squidbuf,squid_file);

// unlock squid passwd file
funlockfile(squid_file);

// close squid temporary file
fclose(squidtmp_file);

// close squid passwd file
fclose(squid_file);

// delete squid temporary file
unlink(TMPSQUIDFILE);

// change user and group for squid passwd file
if (chown(SQUIDPASSWD,0,0)<0) {
	printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br>%s<br><br>%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg28,msg15,msg29,msg08);
	clean_up(1);
}

// change permissions for squid passwd file
if (chmod(SQUIDPASSWD,0644)<0) {
	printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br>%s<br><br>%s<br><br>%s</font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg30,msg15,msg29,msg08);
	clean_up(1);
}

// password in squid passwd file changed!
printf("<font face=\"%s\" color=\"%s\" size=\"%i\">%s<br></font>",FONTFACE,MSGSCOLOR,FONTSIZE,msg31);
}

static void
fixpwd(str)
   unsigned char   *str;
{
   unsigned char   *dest = str;

   while (str[0]) {
      if (str[0] == '+')
         dest[0] = ' ';
      else if (str[0] == '%' && hhex(str[1]) && hhex(str[2])) {
         dest[0] = (unsigned char) htoi(str + 1);
         str += 2;
      } else dest[0] = str[0];

      str++;
      dest++;
   }

   dest[0] = '\0';
   return;
}

static int
htoi(s)
   unsigned char   *s;
{
   int     value;
   char    c;

   c = s[0];
   if (isupper(c))
      c = tolower(c);
   value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;

   c = s[1];
   if (isupper(c))
      c = tolower(c);
   value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;

   return (value);
}
