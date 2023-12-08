/*
   rblcheck DNSBL systems

   Add new sites to this listing in the format:

       // for IP-based DNSBLs
       SITE("site.example.com")
       // for domain-based DNSBLs
       URI_SITE("site.example.com")

   Do not add any extra whitespace, and make sure you place quotes
   around the address. Use C comments in this file if you want to
   add comments about each site. Uncomment the sites you want to use
   by default. The listings are checked in the order they are listed
   here.

   These listings are provided as a convenience, and examples of how to
   add new listings. I'll try to keep them updated if at all possible,
   but you should not rely blindly on these values being correct, nor
   should you rely on someone else's judgement about the "goodness" of
   a particular list; test them, and see if their policies suit your
   tastes. DNSBL-style systems tend to move around a bit, so you should
   check the service websites regularly for updates.

   In other words, if you use one of these, and the world ends, don't
   blame me. You're using them at your own risk. If they break, you get
   to keep both pieces.
*/

/* https://www.spamhaus.org/sbl/ */
SITE("sbl.spamhaus.org");
/* https://www.spamhaus.org/xbl/ */
SITE("xbl.spamhaus.org");
/* https://www.spamhaus.org/pbl/ */
SITE("pbl.spamhaus.org");
/* https://www.spamcop.net/bl.shtml */
SITE("bl.spamcop.net");
/* https://psbl.org/ */
SITE("psbl.surriel.com");
/* http://www.sorbs.net/general/using.shtml */
SITE("dul.dnsbl.sorbs.net");

#ifdef SPAMHAUS_DQS_KEY
/* https://www.spamhaus.org/dbl/ */
URI_SITE(SPAMHAUS_DQS_KEY ".dbl.dq.spamhaus.net.");
#else
/* https://www.spamhaus.org/dbl/ */
URI_SITE("dbl.spamhaus.org");
#endif
/* http://www.surbl.org/lists */
URI_SITE("multi.surbl.org");
/* http://uribl.com/about.shtml */
URI_SITE("multi.uribl.com");

/* http://www.msbl.org/ebl.html */
EMAIL_HASH_SITE("ebl.msbl.org");

