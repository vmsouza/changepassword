#include "conf.h"
#include "info.h"
#include "lang.h"
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <errno.h>
#include <signal.h>
#include <shadow.h>
#include <time.h>

#define hhex(x) (((x) >= '0' && (x) <= '9') || ((x) >= 'a' && (x) <= 'f') || \
                  ((x) >= 'A' && (x) <= 'F'))

#define SHADOW_FILE "/etc/shadow"
#define MAXLEN 1024

void changesmbpass(char *form_user, char *form_newpw1, int buflen);
void changesquidpass(char *form_user, char *form_newpw1, int buflen);
void clean_up(int quit);
void exit_prg(int quit);
void getword(char *word, char *line, char stop) ;
void htmlheader();
void msg(char *msg);
void showform();

int check_passwd(char *pwdstr);
int minpwdlen=PWD_LEN_MIN;
int maxpwdlen=PWD_LEN_MAX;

char denyusers[]="root,bin,daemon,adm,lp,sync,shutdown,halt,mail,news,uucp,operator,games,ftp,smmsp,mysql,gdm,pop,nobody";
char unixdate[11];
char command[128];
char smbencrypted[66];
char oldpwd[PWD_LEN_MAX+1];
char salt[2];
char *dummy;
char *tmp_path;
char *p;

FILE *sd_file;
FILE *tmp_file;
FILE *smb_file;
FILE *smbtmp_file;
FILE *squid_file;
FILE *squidtmp_file;

struct spwd *sd_list;
struct passwd *se_list;

time_t tm;

static int  htoi(unsigned char *s);
static void fixpwd(unsigned char *str);
