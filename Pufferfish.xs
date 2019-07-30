/* Crypt::Pufferfish - an adaptive, cache-hard password hashing scheme
 *
 * Copyright 2019, Jeremi M Gosney. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#define LINUX
#include "include/pufferfish.h"

SV *PF_mksalt (SV *__salt, SV *__cost_t, SV *__cost_m) {
    size_t cost_t  = SvIV(__cost_t);
    size_t cost_m  = SvIV(__cost_m);
    size_t salt_sz = 0;

    char *salt_r = SvPV(__salt, salt_sz);

    char salt[PF_SALTSPACE];

    int ret = 0;

    SV *sv = NULL;

    if ((ret = pf_mksalt(salt_r, salt_sz, cost_t, cost_m, salt)) > 0) {
        sv = newSVpv("", 0);
    } else {
        sv = newSVpv(salt, strlen(salt));
    }

    return newRV_noinc(sv);
}

SV *PF_hash (SV *__salt, SV *__pass) {
    size_t pass_sz = 0;

    char *pass = SvPV(__pass, pass_sz);
    char *salt = SvPV_nolen(__salt);

    char hash[PF_HASHSPACE];

    int ret = 0;

    SV *sv = NULL;

    if ((ret = pf_crypt(salt, pass, pass_sz, hash)) > 0) {
        sv = newSVpv("", 0);
    } else {
        sv = newSVpv(hash, strlen(hash));
    }

    return newRV_noinc(sv);
}

SV *PF_checkpass(SV *__valid, SV *__pass)
{
    size_t pass_sz = 0;

    char *pass = SvPV(__pass, pass_sz);
    char *valid = SvPV_nolen(__valid);

    char hash[PF_HASHSPACE];

    int i, ret = 0, diff = 0;

    if ((ret = pf_crypt(valid, pass, pass_sz, hash)) > 0) {
        return newRV_noinc(newSViv(0));
    }

    diff = strlen(hash) ^ strlen(valid);

    for (i = 0; i < strlen(hash) && i < strlen(valid); i++) {
        diff |= hash[i] ^ valid[i];
    }

    return newRV_noinc(newSViv(diff == 0));
}

MODULE = Crypt::Pufferfish  PACKAGE = Crypt::Pufferfish

PROTOTYPES: DISABLE


SV *
PF_mksalt (__salt, __cost_t, __cost_m)
    SV *__salt
    SV *__cost_t
    SV *__cost_m


SV *
PF_hash (__salt, __pass)
    SV *__salt
    SV *__pass

SV *
PF_checkpass (__valid, __pass)
    SV *__valid
    SV *__pass

