#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <ctype.h>
//#include "utils.c"
#include "common.h"


//extern struct cw_runtime *cw_daemon;

struct option {
    const char *name;
    int has_arg;
    int *flag;
    int val;
};

static struct option opts[] =
{
    {"nameserver", 1, 0, 'S'},
    {"port", 1, 0, 'P'},
    {NULL, 0, 0, 0}
};


void parse_option(int option, char *arg);

void loadcfg(char *fname)
{
    FILE *fp;
    char buf[MAXLINE];
    int option;
    int i;
    char *cfgname, *arg, *p;

    /* set default */
    strcpy(cw_daemon->SOCKS_PORT, "1080");
    strcpy(cw_daemon->DNS_SERVER, "8.8.8.8");

    if ((fp = fopen(fname, "r")) == NULL) {
        fprintf(stderr, "unable open %s\n", fname);
        exit(EXIT_FAILURE);
    }

    memset(buf, 0, sizeof(buf));
    while ((fgets(buf, MAXLINE, fp) != NULL)) {
        //for (p = buf; *p != ' ' && *p != '\t' && *p != '\0'; p++) ;

        // skip to arg
        for (p = buf; (*p == ' ' || *p == '\t') && *p != '\0'; p++)
            ;
        cfgname = p;

        if (*cfgname == '#')
            continue;

        arg = strchr(cfgname, '=');
        if (arg == NULL)
            continue;

        /* remove trailing space from config name */
        for (p = arg - 1; *p == ' ' || *p == '\t'; p--)
            ;
        *++p = '\0';

        for (p = arg; *p != '\0' && (*p == ' ' || *p == '\t' || *p == '='); p++)
            ;
        arg = p;

        /* remove option trailing space and comment */
        for ( ; *p != '\0' && *p != '#' && *p != '\n'; p++)
            ;

        for (--p; *p == ' ' || *p == '\t'; p--)
            ;
        *++p = '\0';

        option = 0;
        for (i = 0; opts[i].name != NULL; i++) {
            if (strcmp(cfgname, opts[i].name) == 0) {
                option = opts[i].val;
            }
        }

        if (option != 0)
            parse_option(option, arg);

    }


    fclose(fp);
}

void parse_option(int option, char *arg)
{

    switch (option) {
    case 'S':
        memset(cw_daemon->DNS_SERVER, 0, sizeof(cw_daemon->DNS_SERVER));
        strncpy(cw_daemon->DNS_SERVER, arg, 15);
        break;
    case 'P':
        memset(cw_daemon->SOCKS_PORT, 0, sizeof(cw_daemon->SOCKS_PORT));
        strncpy(cw_daemon->SOCKS_PORT, arg, 6);
        break;
    }
}
