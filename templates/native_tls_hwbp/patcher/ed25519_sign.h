// Made by Ivan Kozlovsky - https://ivankozlovsky.com - contact@ivankozlovsky.com

/* ed25519_sign.h — Ed25519 detached signing, TweetNaCl subset (public domain) */
#pragma once
#include <stdint.h>
#include <string.h>

/* ed25519_sign_detached: sig[64] = signature of m[mlen] under sk[64] (seed||pubkey) */
static void ed25519_sign_detached(uint8_t sig[64],
                                   const uint8_t *m, size_t mlen,
                                   const uint8_t sk[64]);

/* ════════════════════════════════════════════════════════════
   INTERNALS — all static to avoid linkage conflicts
   ════════════════════════════════════════════════════════════ */
typedef long long _gf[16];
typedef uint64_t  _u64;
typedef uint8_t   _u8;
typedef long long _i64;

/* ── curve constants ──────────────────────────────────────── */
static const _gf _GF0 = {0};
static const _gf _GF1 = {1};
static const _gf _GFD  = {0x78a3,0x1359,0x4dca,0x75eb,0xd8ab,0x4141,0x0a4d,0x0070,
                           0xe898,0x7779,0x4079,0x8cc7,0xfe73,0x2b6f,0x6cee,0x5203};
static const _gf _GFD2 = {0xf159,0x26b2,0x9b94,0xebd6,0xb156,0x8283,0x149a,0x00e0,
                           0xd130,0xeef3,0x80f2,0x198e,0xfce7,0x56df,0xd9dc,0x2406};
static const _gf _GFX  = {0xd51a,0x8f25,0x2d60,0xc956,0xa7b2,0x9525,0xc760,0x692c,
                           0xdc5c,0xfdd6,0xe231,0xc0a4,0x53fe,0xcd6e,0x36d3,0x2169};
static const _gf _GFY  = {0x6658,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,
                           0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666};

static const _i64 _L[32] = {
    0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,
    0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10
};

/* ── SHA-512 ──────────────────────────────────────────────── */
static const _u64 _SHA_K[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

static _u64 _ld64(const _u8 *p){_u64 v=0;for(int i=0;i<8;i++)v=(v<<8)|p[i];return v;}
static void _st64(_u8 *p,_u64 v){for(int i=7;i>=0;i--){p[i]=(_u8)(v&0xff);v>>=8;}}

static void _sha512c(_u64 h[8],const _u8 blk[128]){
    _u64 w[80],a[8],t1,t2;
    for(int i=0;i<16;i++) w[i]=_ld64(blk+i*8);
    for(int i=16;i<80;i++){
        _u64 s0=w[i-15];s0=(s0>>1|s0<<63)^(s0>>8|s0<<56)^(s0>>7);
        _u64 s1=w[i-2]; s1=(s1>>19|s1<<45)^(s1>>61|s1<<3)^(s1>>6);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    for(int i=0;i<8;i++) a[i]=h[i];
    for(int j=0;j<80;j++){
        t1=a[7]+((a[4]>>14|a[4]<<50)^(a[4]>>18|a[4]<<46)^(a[4]>>41|a[4]<<23))
           +((a[4]&a[5])^(~a[4]&a[6]))+_SHA_K[j]+w[j];
        t2=((a[0]>>28|a[0]<<36)^(a[0]>>34|a[0]<<30)^(a[0]>>39|a[0]<<25))
           +((a[0]&a[1])^(a[0]&a[2])^(a[1]&a[2]));
        a[7]=a[6];a[6]=a[5];a[5]=a[4];a[4]=a[3]+t1;
        a[3]=a[2];a[2]=a[1];a[1]=a[0];a[0]=t1+t2;
    }
    for(int i=0;i<8;i++) h[i]+=a[i];
}

/* SHA-512 of (a[la] || b[lb] || c[lc]), any part may be null with len=0 */
static void _sha512m(_u8 out[64],
                     const _u8 *a,size_t la,
                     const _u8 *b,size_t lb,
                     const _u8 *c,size_t lc){
    _u64 h[8]={0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,
                0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
                0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,
                0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};
    size_t total=la+lb+lc;
    _u8 blk[128]; int pos=0;
    const _u8 *ss[3]={a,b,c}; size_t ls[3]={la,lb,lc};
    for(int s=0;s<3;s++)
        for(size_t i=0;i<ls[s];i++){
            blk[pos++]=ss[s][i];
            if(pos==128){_sha512c(h,blk);pos=0;}
        }
    blk[pos++]=0x80;
    if(pos>112){while(pos<128)blk[pos++]=0;_sha512c(h,blk);pos=0;}
    while(pos<112)blk[pos++]=0;
    _st64(blk+112,0); _st64(blk+120,(_u64)total<<3);
    _sha512c(h,blk);
    for(int i=0;i<8;i++) _st64(out+i*8,h[i]);
}

/* ── field arithmetic over GF(2^255-19) ──────────────────── */
static void _gfc(_gf o,const _gf i){for(int k=0;k<16;k++)o[k]=i[k];}
static void _fa(_gf o,const _gf a,const _gf b){for(int i=0;i<16;i++)o[i]=a[i]+b[i];}
static void _fs(_gf o,const _gf a,const _gf b){for(int i=0;i<16;i++)o[i]=a[i]-b[i];}

static void _cr(_gf o){
    _i64 c;
    for(int i=0;i<16;i++){
        o[i]+=(1LL<<16);
        c=o[i]>>16;
        o[(i+1)%16]+=c-1+(i==15)*37*(c-1);
        o[i]-=c<<16;
    }
}

static void _fm(_gf o,const _gf a,const _gf b){
    _i64 t[31]={0};
    for(int i=0;i<16;i++) for(int j=0;j<16;j++) t[i+j]+=a[i]*b[j];
    for(int i=0;i<15;i++) t[i]+=38*t[i+16];
    for(int i=0;i<16;i++) o[i]=t[i];
    _cr(o);_cr(o);
}
static void _fq(_gf o,const _gf a){_fm(o,a,a);}

static void _fsel(_gf p,_gf q,int b){
    _i64 t,mask=-(_i64)b;
    for(int i=0;i<16;i++){t=mask&(p[i]^q[i]);p[i]^=t;q[i]^=t;}
}

static void _finv(_gf o,const _gf inp){
    _gf c; _gfc(c,inp);
    for(int j=253;j>=0;j--){
        _fq(c,c);
        if(j!=2&&j!=4) _fm(c,c,inp);
    }
    _gfc(o,c);
}

static void _fp(_u8 o[32],const _gf n){
    _gf m,t; _gfc(t,n);
    _cr(t);_cr(t);_cr(t);
    for(int j=0;j<2;j++){
        m[0]=t[0]-0xffed;
        for(int i=1;i<15;i++){m[i]=t[i]-0xffff-((m[i-1]>>16)&1);m[i-1]&=0xffff;}
        m[15]=t[15]-0x7fff-((m[14]>>16)&1);
        int bv=(int)(m[15]>>16); m[14]&=0xffff;
        _fsel(t,m,1-bv);
    }
    for(int i=0;i<16;i++){o[2*i]=(_u8)(t[i]&0xff);o[2*i+1]=(_u8)((t[i]>>8)&0xff);}
}
static int _fpar(const _gf a){_u8 d[32];_fp(d,a);return d[0]&1;}

/* ── point arithmetic (extended twisted Edwards coords) ───── */
static void _padd(_gf p[4],_gf q[4]){
    _gf a,b,c,d,e,f,g,hh,t;
    _fs(a,p[1],p[0]); _fs(t,q[1],q[0]); _fm(a,a,t);
    _fa(b,p[0],p[1]); _fa(t,q[0],q[1]); _fm(b,b,t);
    _fm(c,p[3],q[3]); _fm(c,c,_GFD2);
    _fm(d,p[2],q[2]); _fa(d,d,d);
    _fs(e,b,a); _fs(f,d,c); _fa(g,d,c); _fa(hh,b,a);
    _fm(p[0],e,f); _fm(p[1],hh,g); _fm(p[2],g,f); _fm(p[3],e,hh);
}

static void _smult(_gf p[4],_gf q[4],const _u8 s[32]){
    _gfc(p[0],_GF0); _gfc(p[1],_GF1);
    _gfc(p[2],_GF1); _gfc(p[3],_GF0);
    for(int i=255;i>=0;i--){
        _u8 b=(s[i/8]>>(i&7))&1;
        _fsel(p[0],q[0],b); _fsel(p[1],q[1],b);
        _fsel(p[2],q[2],b); _fsel(p[3],q[3],b);
        _padd(q,p);
        _padd(p,p);
        _fsel(p[0],q[0],b); _fsel(p[1],q[1],b);
        _fsel(p[2],q[2],b); _fsel(p[3],q[3],b);
    }
}

static void _sbase(_gf p[4],const _u8 s[32]){
    _gf q[4];
    _gfc(q[0],_GFX); _gfc(q[1],_GFY);
    _gfc(q[2],_GF1); _fm(q[3],_GFX,_GFY);
    _smult(p,q,s);
}

static void _ppack(_u8 o[32],_gf p[4]){
    _gf tx,ty,zi;
    _finv(zi,p[2]); _fm(tx,p[0],zi); _fm(ty,p[1],zi);
    _fp(o,ty);
    o[31]^=(_u8)(_fpar(tx)<<7);
}

/* ── scalar mod l ─────────────────────────────────────────── */
static void _modL(_u8 *r,_i64 x[64]){
    _i64 carry,j,k;
    for(int i=63;i>=32;i--){
        carry=0;
        for(j=i-32,k=i-12;j<k;j++){
            x[j]+=carry-16*x[i]*_L[j-(i-32)];
            carry=(x[j]+128)>>8; x[j]-=carry*256;
        }
        x[j]+=carry; x[i]=0;
    }
    carry=0;
    for(j=0;j<32;j++){
        x[j]+=carry-(x[31]>>4)*_L[j];
        carry=(x[j]+128)>>8; x[j]-=carry*256;
    }
    for(j=0;j<32;j++) x[j]-=carry*_L[j];
    for(int i=0;i<32;i++){x[i+1]+=x[i]>>8;r[i]=(_u8)(x[i]&255);}
}

static void _reduce(_u8 r[64]){
    _i64 x[64];
    for(int i=0;i<64;i++) x[i]=(_i64)(_u8)r[i];
    for(int i=0;i<64;i++) r[i]=0;
    _modL(r,x);
}

/* ── public API ───────────────────────────────────────────── */
static void ed25519_sign_detached(uint8_t sig[64],
                                   const uint8_t *m, size_t mlen,
                                   const uint8_t sk[64]){
    /* 1. Derive scalar a and nonce prefix from seed sk[0..31] */
    uint8_t d[64];
    _sha512m(d, sk,32, nullptr,0, nullptr,0);
    d[0]&=248; d[31]&=127; d[31]|=64;

    /* 2. r = SHA-512(d[32..63] || m) */
    uint8_t r[64];
    _sha512m(r, d+32,32, m,mlen, nullptr,0);

    /* 3. Reduce r mod l → r[0..31] */
    _reduce(r);

    /* 4. R = r * G, encode to sig[0..31] */
    _gf R[4];
    _sbase(R, r);
    _ppack(sig, R);

    /* 5. k = SHA-512(R || pk || m) */
    uint8_t k[64];
    _sha512m(k, sig,32, sk+32,32, m,mlen);

    /* 6. S = (r + k*a) mod l → sig[32..63] */
    _i64 x[64]={};
    for(int i=0;i<32;i++) x[i]=(_i64)(_u8)r[i];
    for(int i=0;i<32;i++) for(int j=0;j<32;j++) x[i+j]+=(_i64)k[i]*(_i64)d[j];
    _modL(sig+32, x);
}

// Made by Ivan Kozlovsky - https://ivankozlovsky.com - contact@ivankozlovsky.com
