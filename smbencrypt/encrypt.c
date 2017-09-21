#include <stdio.h>
#include "nt.h"
char smbencrypted[66];

void smbencrypt(char *pass) {
	char *p=strdup(pass);
	SambaPassGen(p,smbencrypted);
}
