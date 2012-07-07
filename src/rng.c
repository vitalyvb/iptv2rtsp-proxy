/*
------------------------------------------------------------------------------
isaac64.c: My random number generator for 64-bit machines.
By Bob Jenkins, 1996.  Public Domain.
------------------------------------------------------------------------------
*/
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/time.h>

typedef  unsigned long long  ub8;
typedef    signed long long  sb8;
typedef  unsigned       int  ub4;   /* unsigned 4-byte quantities */
typedef    signed       int  sb4;
typedef  unsigned short int  ub2;
typedef    signed short int  sb2;
typedef  unsigned       char ub1;
typedef    signed       char sb1;   /* signed 1-byte quantities */
typedef                 int  word;  /* fastest type available */

#define TRUE  1
#define FALSE 0

#define ISAAC64

#define RANDSIZL   (8)
#define RANDSIZ    (1<<RANDSIZL)

static    ub8 randrsl[RANDSIZ], randcnt=0;
static    ub8 mm[RANDSIZ];
static    ub8 aa=0, bb=0, cc=0;

#define ind(mm,x)  (*(ub8 *)((ub1 *)(mm) + ((x) & ((RANDSIZ-1)<<3))))
#define rngstep(mix,a,b,mm,m,m2,r,x) \
{ \
  x = *m;  \
  a = (mix) + *(m2++); \
  *(m++) = y = ind(mm,x) + a + b; \
  *(r++) = b = ind(mm,y>>RANDSIZL) + x; \
}

static void isaac64()
{
  register ub8 a,b,x,y,*m,*m2,*r,*mend;
  m=mm; r=randrsl;
  a = aa; b = bb + (++cc);
  for (m = mm, mend = m2 = m+(RANDSIZ/2); m<mend; )
  {
    rngstep(~(a^(a<<21)), a, b, mm, m, m2, r, x);
    rngstep(  a^(a>>5)  , a, b, mm, m, m2, r, x);
    rngstep(  a^(a<<12) , a, b, mm, m, m2, r, x);
    rngstep(  a^(a>>33) , a, b, mm, m, m2, r, x);
  }
  for (m2 = mm; m2<mend; )
  {
    rngstep(~(a^(a<<21)), a, b, mm, m, m2, r, x);
    rngstep(  a^(a>>5)  , a, b, mm, m, m2, r, x);
    rngstep(  a^(a<<12) , a, b, mm, m, m2, r, x);
    rngstep(  a^(a>>33) , a, b, mm, m, m2, r, x);
  }
  bb = b; aa = a;
}

#define mix(a,b,c,d,e,f,g,h) \
{ \
   a-=e; f^=h>>9;  h+=a; \
   b-=f; g^=a<<9;  a+=b; \
   c-=g; h^=b>>23; b+=c; \
   d-=h; a^=c<<15; c+=d; \
   e-=a; b^=d>>14; d+=e; \
   f-=b; c^=e<<20; e+=f; \
   g-=c; d^=f>>17; f+=g; \
   h-=d; e^=g<<14; g+=h; \
}

static void randinit(flag)
word flag;
{
   word i;
   ub8 a,b,c,d,e,f,g,h;
   aa=bb=cc=(ub8)0;
   a=b=c=d=e=f=g=h=0x9e3779b97f4a7c13LL;  /* the golden ratio */

   for (i=0; i<4; ++i)                    /* scramble it */
   {
     mix(a,b,c,d,e,f,g,h);
   }

   for (i=0; i<RANDSIZ; i+=8)   /* fill in mm[] with messy stuff */
   {
     if (flag)                  /* use all the information in the seed */
     {
       a+=randrsl[i  ]; b+=randrsl[i+1]; c+=randrsl[i+2]; d+=randrsl[i+3];
       e+=randrsl[i+4]; f+=randrsl[i+5]; g+=randrsl[i+6]; h+=randrsl[i+7];
     }
     mix(a,b,c,d,e,f,g,h);
     mm[i  ]=a; mm[i+1]=b; mm[i+2]=c; mm[i+3]=d;
     mm[i+4]=e; mm[i+5]=f; mm[i+6]=g; mm[i+7]=h;
   }

   if (flag) 
   {        /* do a second pass to make all of the seed affect all of mm */
     for (i=0; i<RANDSIZ; i+=8)
     {
       a+=mm[i  ]; b+=mm[i+1]; c+=mm[i+2]; d+=mm[i+3];
       e+=mm[i+4]; f+=mm[i+5]; g+=mm[i+6]; h+=mm[i+7];
       mix(a,b,c,d,e,f,g,h);
       mm[i  ]=a; mm[i+1]=b; mm[i+2]=c; mm[i+3]=d;
       mm[i+4]=e; mm[i+5]=f; mm[i+6]=g; mm[i+7]=h;
     }
   }

   isaac64();          /* fill in the first set of results */
   randcnt=RANDSIZ;    /* prepare to use the first set of results */
}


int my_random_init()
{
    struct timeval tv;
    FILE *randf;
    size_t bufread;
    int i;

    aa = 0;
    bb = 0;
    cc = 0;

    for (i=0; i<RANDSIZ; ++i)
	mm[i] = 0;

    for (i=0; i<RANDSIZ; ++i)
	randrsl[0] = 0;

    randf = fopen("/dev/urandom", "rb");
    bufread = sizeof(randrsl);
    if (randf == NULL){
	randf = fopen("/dev/random", "rb");
	// do not use system entropy too much
	bufread = 3;
    }

    if (randf != NULL){
	bufread = fread(randrsl, 1, bufread, randf);
	//printf("read %d random bytes\n", bufread);
	fclose(randf);
    } else {
	bufread = 0;
    }

    if (bufread < sizeof(randrsl)){
	size_t room_left = sizeof(randrsl) - bufread;
	size_t len;

	if (gettimeofday(&tv, NULL) == 0){
	    len = (sizeof(tv) > room_left) ? room_left : sizeof(tv);
	    // append
	    memcpy(&((char*)randrsl)[bufread], &tv, len);
	    //printf("added %d bytes from timeval at %d\n", len, bufread);
	    bufread += len;
	}
    }

    randinit(TRUE);


    return 0;
}

long my_rand()
{
    if (randcnt == 0) {
	isaac64();
	randcnt=RANDSIZ-1;
    } else {
	randcnt--;
    }

    return randrsl[randcnt];
}

#ifdef TEST_CAST
int main()
{
    int j;

    my_random_init();

    for (j=0;j<20;j++){
	printf("%16lx %16lx\n", my_rand(), my_rand());
    }

    return 0;
}
#endif

