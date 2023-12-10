/*
** rblcheck - Command-line interface to RBL-style filters.
**
** Copyright (C) 1997, 1998, 1999, 2000, 2001,
** Edward S. Marshall <esm@logic.net>
**
** Copyright (C) 2019-2023 Marco d'Itri <md@linux.it>.
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
#include "utils.h"
#include "base32.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef WITH_HASHED_DNSBLS
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>

#ifdef HAVE_OPENSSL_EVP
#include <openssl/err.h>
#include <openssl/evp.h>
#elif defined HAVE_LIBCRYPTO
#include <openssl/sha.h>
#elif defined HAVE_LIBNETTLE
#include <nettle/sha1.h>
#include <nettle/sha2.h>
#endif
#endif

/*-- LOCAL DEFINITIONS ------------------------------------------------------*/

#define RESULT_SIZE 4096	/* What is the longest result text we support? */

/* The values returned by query_type(). */
enum query_types {
    RBLCHECK_IP,
    RBLCHECK_DOMAIN,
    RBLCHECK_EMAIL,
    RBLCHECK_FILE,
};

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
    struct rbl *uribls;
    struct rbl *emailhashbls;
    struct rbl *filehashbls;
    int firstmatch;
    int quiet;
    int txt;
};

/*-- PROTOTYPES -------------------------------------------------------------*/
void version(void);
void usage(void);
struct rbl *togglesite(const char *, struct rbl *);
struct rbl *cleanlist(struct rbl *);
char *rblcheck_ip(const char *, char *, int);
char *rblcheck_domain(const char *, char *, int);
char *rblcheck_email(const char *, char *, int);
char *rblcheck_file(const char *, char *, int);
char *query_dns(const char *, const int);
int query_type(const char *);
int full_rblcheck(char *, struct opts *);
char *canonicalize_email_address(const char *);
size_t read_file(const char *, char **);
char *sha_1_base16(const char *, size_t);
char *sha_256_base32(const char *, size_t);

/*-- FUNCTIONS --------------------------------------------------------------*/

/* version()
 * Display the version of this program back to the user. */
void version(void)
{
    fprintf(stderr,
	    "%s %s\nCopyright (C) 1997, 1998, 1999, 2000, 2001 Edward S. Marshall\n"
	    "Copyright (C) 2019-2023 Marco d'Itri\n",
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
    <address>    An IP or email address or file to look up;\n\
                 specify '@/file/name' to read a file;\n\
		 specify '-' to read multiple elements from standard input.\n",
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

struct rbl *cleanlist(struct rbl *list)
{
    struct rbl *ptr;

    ptr = list;
    while (ptr != NULL) {
	list = ptr->next;
	free(ptr->site);
	free(ptr);
	ptr = list;
    }

    return list;
}

/* rblcheck_ip()
 * Checks the specified dotted-quad address against the provided RBL
 * domain. If "txt" is non-zero, we perform a TXT record lookup. We
 * return the text returned from a TXT match, or an empty string, on
 * a successful match, or NULL on an unsuccessful match. */
char *rblcheck_ip(const char *addr, char *rbldomain, int txt)
{
    char *domain;

#ifdef HAVE_GETADDRINFO
    struct addrinfo *res = NULL;
    struct addrinfo hints;
    int rc;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

    rc = getaddrinfo(addr, NULL, &hints, &res);
    if (rc == EAI_NONAME || res == NULL)
	err_quit("warning: invalid address '%s'", addr);
    if (rc < 0)
	err_quit("warning: getaddrinfo(%s): %s", addr, gai_strerror(rc));

    /* 32 characters and 32 dots in a reversed v6 address, plus 1 for null */
    domain = NOFAIL(malloc(32 + 32 + 1 + strlen(rbldomain)));

    if (res->ai_family == AF_INET) {
	struct sockaddr_in *saddr = (struct sockaddr_in *) res->ai_addr;
	unsigned char *a = (unsigned char *) &(saddr->sin_addr);

	sprintf(domain, "%d.%d.%d.%d.%s",
		*(a + 3), *(a + 2), *(a + 1), *a, rbldomain);
    } else if (res->ai_family == AF_INET6) {
	struct sockaddr_in6 *saddr = (struct sockaddr_in6 *) res->ai_addr;
	unsigned char *a = (unsigned char *) &(saddr->sin6_addr);

	sprintf(domain,
		"%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
		"%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%s",
		*(a + 15) & 0xF, *(a + 15) >> 4,
		*(a + 14) & 0xF, *(a + 14) >> 4,
		*(a + 13) & 0xF, *(a + 13) >> 4,
		*(a + 12) & 0xF, *(a + 12) >> 4,
		*(a + 11) & 0xF, *(a + 11) >> 4,
		*(a + 10) & 0xF, *(a + 10) >> 4,
		*(a +  9) & 0xF, *(a +  9) >> 4,
		*(a +  8) & 0xF, *(a +  8) >> 4,
		*(a +  7) & 0xF, *(a +  7) >> 4,
		*(a +  6) & 0xF, *(a +  6) >> 4,
		*(a +  5) & 0xF, *(a +  5) >> 4,
		*(a +  4) & 0xF, *(a +  4) >> 4,
		*(a +  3) & 0xF, *(a +  3) >> 4,
		*(a +  2) & 0xF, *(a +  2) >> 4,
		*(a +  1) & 0xF, *(a +  1) >> 4,
		*(a +  0) & 0xF, *(a +  0) >> 4,
		rbldomain
	);
    } else {
	err_quit("getaddrinfo(%s) returned ai_family=%d!",
		addr, res->ai_family);
    }

    freeaddrinfo(res);
#else
    int a, b, c, d;

    if (sscanf(addr, "%d.%d.%d.%d", &a, &b, &c, &d) != 4
	    || a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255
	    || d < 0 || d > 255) {
	err_quit("warning: invalid address '%s'", addr);

    /* 16 characters max in a dotted-quad address, plus 1 for null */
    domain = NOFAIL(malloc(17 + strlen(rbldomain)));

    /* Create a domain name, in reverse. */
    sprintf(domain, "%d.%d.%d.%d.%s", d, c, b, a, rbldomain);
#endif

    return query_dns(domain, txt);
}

char *query_dns(const char *domain, const int txt)
{
    char *result = NULL;
    unsigned char fixedans[PACKETSZ];
    unsigned char *answer;
    const unsigned char *cp;
    char *rp;
    const unsigned char *cend;
    const char *rend;
    int len;

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

char *rblcheck_domain(const char *addr, char *rbldomain, int txt)
{
    char *domain, *result;

    domain = NOFAIL(malloc(strlen(addr) + 1 + strlen(rbldomain) + 1));
    strcpy(domain, addr);
    strcat(domain, ".");
    strcat(domain, rbldomain);

    result = query_dns(domain, txt);
    free(domain);
    return result;
}

#ifdef WITH_HASHED_DNSBLS

/* https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/030-datasets.html#email-email */
char *canonicalize_email_address(const char *email)
{
    char *at, *plus, *canonical;

    canonical = NOFAIL(malloc(strlen(email) + 1));

    /* copy the address and convert it to lower case */
    for(int i = 0; email[i] != '\0'; i++)
	canonical[i] = tolower(email[i]);

    at = strchr(canonical, '@');
    if (!at)
	return canonical;

    /* remove the +parameter from the left part */
    plus = strchr(canonical, '+');
    if (plus && (at - plus) > 0)
	memmove(plus, at, strlen(at) + 1);

    /* replace @googlemail.com with @gmail.com */
    if (strcmp(at + 1, "googlemail.com") == 0)
	strcpy(at + 1, "gmail.com");

    if (strcmp(at + 1, "gmail.com") == 0) {
	/* remove the dots from the left part */
	char *s = canonical;
	char *d = canonical;
	int copy = 0;

	do {
	    if (*s == '@')
		copy = 1;
	    if (copy || *s != '.')
		*d++ = *s;
	} while (*s++ != '\0');
    }

    return canonical;
}

size_t read_file(const char *path, char **buf_result)
{
    int fd;
    char buf[4096];
    ssize_t n;
    char *str = NULL;
    size_t len = 0;

    fd = open(path, O_RDONLY);
    if (fd < 0)
	err_sys("cannot open file '%s'", path);

    while ((n = read(fd, buf, sizeof(buf))) > 0) {
	if (n < 0) {
	    if (errno == EAGAIN)
		continue;
	    err_sys("cannot read file '%s'", path);
	}
	str = realloc(str, len + n + 1);
	memcpy(str + len, buf, n);
	len += n;
	str[len] = '\0';
    }

    close(fd);
    *buf_result = str;
    return len;
}

char *rblcheck_email(const char *email, char *rbldomain, int txt)
{
    char *hash, *canon_email, *result;

    canon_email = canonicalize_email_address(email);
#ifdef WITH_SHA_256_EMAIL_HASHES
    hash = sha_256_base32(canon_email, strlen(canon_email));
#else
    hash = sha_1_base16(canon_email, strlen(canon_email));
#endif
    free(canon_email);
    result = rblcheck_domain(hash, rbldomain, txt);
    free(hash);
    return result;
}

char *rblcheck_file(const char *path, char *rbldomain, int txt)
{
    char *hash, *file_content, *result;
    size_t length;

    length = read_file(path, &file_content);
    hash = sha_256_base32(file_content, length);
    free(file_content);
    result = rblcheck_domain(hash, rbldomain, txt);
    free(hash);
    return result;
}

#ifdef HAVE_OPENSSL_EVP

unsigned char *openssl_hash(const char *, size_t, const EVP_MD*);

unsigned char *openssl_hash(const char *buf, size_t length, const EVP_MD *type)
{
    EVP_MD_CTX *ctx;
    static unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_length;

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        printf("EVP_MD_CTX_new() failed: %s!\n",
		ERR_error_string(ERR_get_error(), NULL));
        exit(-1);
    }

    if (!EVP_DigestInit_ex(ctx, type, NULL)) {
        printf("EVP_DigestInit_ex() failed: %s!\n",
		ERR_error_string(ERR_get_error(), NULL));
        exit(-1);
    }

    if (!EVP_DigestUpdate(ctx, buf, length)) {
        printf("EVP_DigestUpdate() failed: %s!\n",
		ERR_error_string(ERR_get_error(), NULL));
        exit(-1);
    }

    if (!EVP_DigestFinal_ex(ctx, hash, &hash_length)) {
        printf("EVP_DigestFinal_ex() failed: %s!\n",
		ERR_error_string(ERR_get_error(), NULL));
        exit(-1);
    }

    EVP_MD_CTX_free(ctx);

    return hash;
}

char *sha_1_base16(const char *buf, size_t length)
{
    unsigned char *hash;

    hash = openssl_hash(buf, length, EVP_sha1());
    return NOFAIL(base16_encode(hash, 20));
}

char *sha_256_base32(const char *buf, size_t length)
{
    unsigned char *hash;

    hash = openssl_hash(buf, length, EVP_sha256());
    return NOFAIL(base32_encode(hash, 32));
}

#elif defined HAVE_LIBCRYPTO

char *sha_1_base16(const char *buf, size_t length)
{
    SHA_CTX ctx;
    unsigned char hash[SHA_DIGEST_LENGTH];

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, buf, length);
    SHA1_Final(hash, &ctx);

    return NOFAIL(base16_encode(hash, SHA_DIGEST_LENGTH));
}

char *sha_256_base32(const char *buf, size_t length)
{
    SHA256_CTX ctx;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, buf, length);
    SHA256_Final(hash, &ctx);

    return NOFAIL(base32_encode(hash, SHA256_DIGEST_LENGTH));
}

#elif defined HAVE_LIBNETTLE

char *sha_1_base16(const char *buf, size_t length)
{
    struct sha1_ctx ctx;
    unsigned char hash[SHA1_DIGEST_SIZE];

    sha1_init(&ctx);
    sha1_update(&ctx, length, (const uint8_t *)buf);
    sha1_digest(&ctx, SHA1_DIGEST_SIZE, hash);

    return NOFAIL(base16_encode(hash, SHA1_DIGEST_SIZE));
}

char *sha_256_base32(const char *buf, size_t length)
{
    struct sha256_ctx ctx;
    unsigned char hash[SHA256_DIGEST_SIZE];

    sha256_init(&ctx);
    sha256_update(&ctx, length, (const uint8_t *)buf);
    sha256_digest(&ctx, SHA256_DIGEST_SIZE, hash);

    return NOFAIL(base32_encode(hash, SHA256_DIGEST_SIZE));
}

#else
#error "No crypto library has been enabled"
#endif

#else /* WITH_HASHED_DNSBLS */

char *rblcheck_email(const char *email, char *rbldomain, int txt)
{
    err_quit("Support for hashed DNSBLs is not enabled!");
}

char *rblcheck_file(const char *email, char *rbldomain, int txt)
{
    return rblcheck_email(email, rbldomain, txt);
}

#endif /* WITH_HASHED_DNSBLS */

int query_type(const char *s)
{
    const char *p;

    /* is a file name */
    if (s[0] == '@')
	return RBLCHECK_FILE;

    /* looks like an email address */
    if (strrchr(s, '@'))
	return RBLCHECK_EMAIL;

    /* not a valid domain, but hopefully a valid IPv6 address */
    if (strrchr(s, ':'))
	return RBLCHECK_IP;

    /* does not contain a dot nor a colon, so it is not a v4 or v6 IP */
    p = strrchr(s, '.');
    if (!p)
	return RBLCHECK_DOMAIN;

    /* check the character after the dot */
    p++;

    /* a trailing dot is invalid, so have getaddrinfo() fail on it */
    if (*p == '\0')
	return RBLCHECK_IP;

    /* contains an alphabetic character */
    for (p = s; *p != '\0'; p++)
	if ((*p >= 'a' && *p <= 'z') || (*p >= 'a' && *p <= 'z'))
	    return RBLCHECK_DOMAIN;

    return RBLCHECK_IP;
}

/* full_rblcheck
 * Takes an IP address, and feeds it to rblcheck() for each defined
 * RBL listing, handling output of results if necessary. */
int full_rblcheck(char *addr, struct opts *opt)
{
    int count = 0;
    int type;
    char *response;
    struct rbl *ptr;

    type = query_type(addr);
    if (type == RBLCHECK_DOMAIN)
	ptr = opt->uribls;
    else if (type == RBLCHECK_EMAIL)
	ptr = opt->emailhashbls;
    else if (type == RBLCHECK_FILE)
	ptr = opt->filehashbls;
    else
	ptr = opt->rblsites;

    for (; ptr != NULL; ptr = ptr->next) {
	if (type == RBLCHECK_DOMAIN)
	    response = rblcheck_domain(addr, ptr->site, opt->txt);
	else if (type == RBLCHECK_EMAIL)
	    response = rblcheck_email(addr, ptr->site, opt->txt);
	else if (type == RBLCHECK_FILE)
	    response = rblcheck_file(addr + 1, ptr->site, opt->txt);
	else
	    response = rblcheck_ip(addr, ptr->site, opt->txt);
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
#define URI_SITE(x) opt->uribls = togglesite( (x), opt->uribls );
#define EMAIL_HASH_SITE(x) opt->emailhashbls = \
    togglesite( (x), opt->emailhashbls );
#define FILE_HASH_SITE(x) opt->filehashbls = \
    togglesite( (x), opt->filehashbls );
#include "sites.h"
#undef SITE
#undef URI_SITE
#undef EMAIL_HASH_SITE
#undef FILE_HASH_SITE

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
	    if (opt->rblsites)
		puts("# IP-based DNSBLs:");
	    for (ptr = opt->rblsites; ptr != NULL; ptr = ptr->next)
		printf("%s\n", ptr->site);
	    if (opt->uribls)
		puts("# Domain-based DNSBLs:");
	    for (ptr = opt->uribls; ptr != NULL; ptr = ptr->next)
		printf("%s\n", ptr->site);
	    if (opt->emailhashbls)
		puts("# Email-based DNSBLs:");
	    for (ptr = opt->emailhashbls; ptr != NULL; ptr = ptr->next)
		printf("%s\n", ptr->site);
	    if (opt->filehashbls)
		puts("# File-based DNSBLs:");
	    for (ptr = opt->filehashbls; ptr != NULL; ptr = ptr->next)
		printf("%s\n", ptr->site);
	    exit(0);
	case 's':
	    /* Toggle a particular zone. */
	    opt->rblsites = togglesite(optarg, opt->rblsites);
	    opt->uribls = togglesite(optarg, opt->uribls);
	    opt->emailhashbls = togglesite(optarg, opt->emailhashbls);
	    opt->filehashbls = togglesite(optarg, opt->filehashbls);
	    break;
	case 'c':
	    /* Clear the rbl zones. */
	    opt->rblsites = cleanlist(opt->rblsites);
	    opt->uribls = cleanlist(opt->uribls);
	    opt->emailhashbls = cleanlist(opt->emailhashbls);
	    opt->filehashbls = cleanlist(opt->filehashbls);
	    break;
	case '?':
	case 'h':
	    /* Help */
	    usage();
	    exit(0);
	case 'v':
	    /* Version */
	    version();
	    exit(0);
	}

    /* Did they tell us to check anything? */
    if (optind == argc) {
	fprintf(stderr, "%s: no address(es) specified\n", progname);
	usage();
	exit(-1);
    }

    /* Do we have any listings to search? */
    if (!opt->rblsites)
	err_quit("no DNSBL domains(s) specified (need '-s <domain>'?)");

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

    exit(rblfiltered);
}

