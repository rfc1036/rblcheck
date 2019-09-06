/*
** rblcheck - Command-line interface to RBL-style filters.
** Copyright (C) 1997, 1998, 1999, 2000, 2001,
** Edward S. Marshall <esm@logic.net>
**
** Copyright (C) 2019 Marco d'Itri <md@linux.it>.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

/*-- LOCAL DEFINITIONS ------------------------------------------------------*/

#define RESULT_SIZE 4096	/* What is the longest result text we support? */

/*-- GLOBAL VARIABLES -------------------------------------------------------*/

/* Simple linked list to hold the sites we support. See sites.h. */
struct rbl {
    char *site;
    struct rbl *next;
};

/* Name the program was invoked as. */
const char *progname;

/* Global options. */
struct opts {
    struct rbl *rblsites;
    int firstmatch;
    int quiet;
    int txt;
};

/*-- PROTOTYPES -------------------------------------------------------------*/
void *do_nofail(void *, const char *, const int);
void version(void);
void usage(void);
struct rbl *togglesite(const char *, struct rbl *);
char *rblcheck(const char *, char *, int);
int full_rblcheck(char *, struct opts *);

/*-- FUNCTIONS --------------------------------------------------------------*/

void *do_nofail(void *ptr, const char *file, const int line)
{
    if (ptr)
	return ptr;

    fprintf(stderr, "Memory allocation failure at %s:%d.", file, line);
    exit(1);
}

#define NOFAIL(ptr) do_nofail((ptr), __FILE__, __LINE__)

/* version()
 * Display the version of this program back to the user. */
void version(void)
{
    fprintf(stderr,
	    "%s %s\nCopyright (C) 1997, 1998, 1999, 2000, 2001 Edward S. Marshall\n"
	    "Copyright (C) 2019 Marco d'Itri\n",
	    PACKAGE, VERSION);
}

/* usage()
 * Display how to use this program back to the user. */
void usage(void)
{
    version();
    fprintf(stderr,
	    "Usage: %s [-qtlcvh?] [-s <service>] <address> [ <address> ... ]\n\
\n\
    -q           Quiet mode; print only listed addresses\n\
    -t           Print a TXT record, if any\n\
    -m           Stop checking after first address match in any list\n\
    -l           List default DNSBL services to check\n\
    -c           Clear the current list of DNSBL services\n\
    -s <service> Toggle a service to the DNSBL services list\n\
    -h, -?       Display this help message\n\
    -v           Display version information\n\
    <address>    An IP address to look up; specify '-' to read multiple\n\
                 addresses from standard input.\n",
	    progname);
}

/* togglesite()
 * This function takes the name of the site, and either adds it to the
 * list of sites to check, or removes it if it already exists. */
struct rbl *togglesite(const char *sitename, struct rbl *sites)
{
    struct rbl *ptr;
    struct rbl *last = NULL;
    size_t sitelen;

    sitelen = strlen(sitename);

    for (ptr = sites; ptr != NULL; last = ptr, ptr = ptr->next) {
	if ((strlen(ptr->site) == sitelen) &&
	    (!strcmp(ptr->site, sitename))) {
	    if (last)
		last->next = ptr->next;
	    else
		sites = ptr->next;
	    free(ptr->site);
	    free(ptr);
	    return sites;
	}
    }
    ptr = NOFAIL(malloc(sizeof(struct rbl)));
    if (last)
	last->next = ptr;
    else
	sites = ptr;
    ptr->site = NOFAIL(malloc(sitelen + 1));
    strcpy(ptr->site, sitename);
    ptr->next = NULL;
    return sites;
}

/* rblcheck()
 * Checks the specified dotted-quad address against the provided RBL
 * domain. If "txt" is non-zero, we perform a TXT record lookup. We
 * return the text returned from a TXT match, or an empty string, on
 * a successful match, or NULL on an unsuccessful match. */
char *rblcheck(const char *addr, char *rbldomain, int txt)
{
    char *domain;
    char *result = NULL;
    unsigned char fixedans[PACKETSZ];
    unsigned char *answer;
    const unsigned char *cp;
    char *rp;
    const unsigned char *cend;
    const char *rend;
    int len;
    int a, b, c, d;

    if (sscanf(addr, "%d.%d.%d.%d", &a, &b, &c, &d) != 4
	    || a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255
	    || d < 0 || d > 255) {
	fprintf(stderr, "%s: warning: invalid address '%s'\n", progname, addr);
	return 0;
    }

    /* 16 characters max in a dotted-quad address, plus 1 for null */
    domain = NOFAIL(malloc(17 + strlen(rbldomain)));

    /* Create a domain name, in reverse. */
    sprintf(domain, "%d.%d.%d.%d.%s", d, c, b, a, rbldomain);

    /* Make our DNS query. */
    res_init();
    answer = fixedans;
    len = res_query(domain, C_IN, T_A, answer, PACKETSZ);

    /* Was there a problem? If so, the domain doesn't exist. */
    if (len == -1)
	return result;

    if (len > PACKETSZ) {
	answer = NOFAIL(malloc(len));
	len = res_query(domain, C_IN, T_A, answer, len);
	if (len == -1)
	    return result;
    }

    result = NOFAIL(malloc(RESULT_SIZE));
    result[0] = '\0';
    if (!txt) {
	return result;
    }

    /* Make another DNS query for textual data; this shouldn't
       be a performance hit, since it'll now be cached at the
       nameserver we're using. */
    res_init();
    len = res_query(domain, C_IN, T_TXT, answer, PACKETSZ);

    /* Just in case there's no TXT record... */
    if (len == -1) {
	return result;
    }

    /* Skip the header and the address we queried. */
    cp = answer + sizeof(HEADER);
    while (*cp != '\0') {
	unsigned char p;
	p = *cp++;
	while (p--)
	    cp++;
    }

    /* This seems to be a bit of magic data that we need to
       skip. I wish there were good online documentation
       for programming for libresolv, so I'd know what I'm
       skipping here. Anyone reading this, feel free to
       enlighten me. */
    cp += 1 + NS_INT16SZ + NS_INT32SZ;

    /* Skip the type, class and ttl. */
    cp += (NS_INT16SZ * 2) + NS_INT32SZ;

    /* Get the length and end of the buffer. */
    NS_GET16(len, cp);
    cend = cp + len;

    /* Iterate over any multiple answers we might have. In
       this context, it's unlikely, but anyway. */
    rp = result;
    rend = result + RESULT_SIZE - 1;
    while (cp < cend && rp < rend) {
	unsigned char p;
	p = *cp++;
	if (p != 0) {
	    unsigned char x;
	    for (x = p; x > 0 && cp < cend && rp < rend; x--) {
		if (*cp == '\n' || *cp == '"' || *cp == '\\') {
		    *rp++ = '\\';
		}
		*rp++ = *cp++;
	    }
	}
    }
    *rp = '\0';
    return result;
}

/* full_rblcheck
 * Takes an IP address, and feeds it to rblcheck() for each defined
 * RBL listing, handling output of results if necessary. */
int full_rblcheck(char *addr, struct opts *opt)
{
    int count = 0;
    char *response;
    struct rbl *ptr;

    for (ptr = opt->rblsites; ptr != NULL; ptr = ptr->next) {
	response = rblcheck(addr, ptr->site, opt->txt);
	if (!opt->quiet || response)
	    printf("%s %s%s%s%s%s%s", addr,
		   (!opt->quiet && !response ? "not " : ""),
		   (!opt->quiet ? "listed by " : ""),
		   (!opt->quiet ? ptr->site : ""),
		   (opt->txt && response && strlen(response) && !opt->quiet ?
		    ": " : ""),
		   (opt->txt && response ? response : ""),
		   (opt->quiet && (!opt->txt || (response &&
				       !strlen(response))) ? "" : "\n"));
	if (response) {
	    count++;
	    free(response);
	}
	if (opt->firstmatch && count)
	    return count;
    }
    return count;
}

/*-- MAINLINE ---------------------------------------------------------------*/

int main(int argc, char *argv[])
{
    int a;
    struct opts *opt;
    struct rbl *ptr;
    int rblfiltered = 0;
    char inbuf[RESULT_SIZE];

    opt = NOFAIL(calloc(1, sizeof(struct opts)));

/* Hack to handle the easy addition of sites at compile time. */
#define SITE(x) opt->rblsites = togglesite( (x), opt->rblsites );
#include "sites.h"
#undef SITE

    progname = argv[0];

    while ((a = getopt(argc, argv, "qtlms:c?hv")) != EOF)
	switch (a) {
	case 'q':
	    /* Quiet mode. */
	    opt->quiet = 1;
	    break;
	case 't':
	    /* Display TXT record. */
	    opt->txt = 1;
	    break;
	case 'm':
	    /* Stop after first successful match. */
	    opt->firstmatch = 1;
	    break;
	case 'l':
	    /* Display supported RBL systems. */
	    for (ptr = opt->rblsites; ptr != NULL; ptr = ptr->next)
		printf("%s\n", ptr->site);
	    return 0;
	case 's':
	    /* Toggle a particular zone. */
	    opt->rblsites = togglesite(optarg, opt->rblsites);
	    break;
	case 'c':
	    /* Clear the rbl zones. */
	    ptr = opt->rblsites;
	    while (ptr != NULL) {
		opt->rblsites = ptr->next;
		free(ptr->site);
		free(ptr);
		ptr = opt->rblsites;
	    }
	    break;
	case '?':
	case 'h':
	    /* Help */
	    usage();
	    return 0;
	case 'v':
	    /* Verision */
	    version();
	    return 0;
	}

    /* Did they tell us to check anything? */
    if (optind == argc) {
	fprintf(stderr, "%s: no IP address(es) specified\n", progname);
	usage();
	return -1;
    }

    /* Do we have any listings to search? */
    if (!opt->rblsites) {
	fprintf(stderr,
		"%s: no rbl listing(s) specified (need '-s <zone>'?)\n",
		progname);
	return 0;
    }

    /* Loop through the command line. */
    while (optind < argc) {
	/* Handle addresses from stdin. */
	if (argv[optind][0] == '-' && argv[optind][1] == '\0')
	    while (fgets(inbuf, RESULT_SIZE - 1, stdin) != NULL) {
		inbuf[strlen(inbuf) - 1] = '\0';
		rblfiltered += full_rblcheck(inbuf, opt);
		if (opt->firstmatch && rblfiltered)
		    return rblfiltered;
	} else
	    rblfiltered += full_rblcheck(argv[optind], opt);
	if (opt->firstmatch && rblfiltered)
	    return rblfiltered;
	optind++;
    }

    return rblfiltered;
}

