#include "cotp.h"
#include "utils/secure_zero.h"
#include "whmac.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>


/**
 * @file otp.c
 * @brief Heap-free implementation of HOTP and TOTP.
 */

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define REVERSE_BYTES(C, C_reverse_byte_order)                                 \
  for (int j = 0, i = 7; j < 8; j++, i--) {                                    \
    (C_reverse_byte_order)[i] = ((unsigned char *)&(C))[j];                    \
  }
#else
#define REVERSE_BYTES(C, C_reverse_byte_order)                                 \
  for (int j = 0; j < 8; j++) {                                                \
    (C_reverse_byte_order)[j] = ((unsigned char *)&(C))[j];                    \
  }
#endif

static int check_algo(int algo) {
  return (algo != SHA1 && algo != SHA256 && algo != SHA512) ? -1 : 0;
}

static int check_otp_len(int digits_length) {
  return (digits_length < 4 || digits_length > 10) ? -1 : 0;
}

static int check_period(int period) {
  return (period <= 0 || period > 120) ? -1 : 0;
}

static size_t b32_decoded_len_from_str(const char *s) {
  if (!s)
    return 0;
  size_t chars = 0;
  for (const char *p = s; *p; ++p) {
    if (*p != '=' && *p != ' ') {
      ++chars;
    }
  }
  return (chars * 5) / 8;
}

static int truncate(const unsigned char *hmac, int digits_length,
                    whmac_handle_t *hd) {
  size_t hlen = whmac_getlen(hd);
  int offset = hmac[hlen - 1] & 0x0f;
  uint32_t bin_code = ((uint32_t)(hmac[offset] & 0x7f) << 24) |
                      ((uint32_t)(hmac[offset + 1] & 0xff) << 16) |
                      ((uint32_t)(hmac[offset + 2] & 0xff) << 8) |
                      ((uint32_t)(hmac[offset + 3] & 0xff));

  uint64_t mod = 1;
  for (int i = 0; i < digits_length; ++i)
    mod *= 10ULL;
  return (int)(((uint64_t)bin_code) % mod);
}

static bool compute_hmac_buf(const char *K, long C, whmac_handle_t *hd,
                             unsigned char *out_hmac, size_t *out_len) {
  char normalized_K[128];
  size_t j = 0;
  for (int i = 0; K[i] != '\0' && j < sizeof(normalized_K) - 1; i++) {
    if (K[i] != ' ') {
      normalized_K[j++] =
          (K[i] >= 'a' && K[i] <= 'z') ? (char)(K[i] - 'a' + 'A') : K[i];
    }
  }
  normalized_K[j] = '\0';

  size_t secret_len = b32_decoded_len_from_str(normalized_K);
  unsigned char secret[64];
  if (secret_len > sizeof(secret))
    return false;

  cotp_error_t err;
  if (!base32_decode_buf(normalized_K, strlen(normalized_K), secret,
                         sizeof(secret), &err))
    return false;

  unsigned char C_reverse_byte_order[8];
  REVERSE_BYTES(C, C_reverse_byte_order);

  if (whmac_setkey(hd, secret, secret_len) != 0) {
    memset(secret, 0, sizeof(secret));
    return false;
  }
  whmac_update(hd, C_reverse_byte_order, sizeof(C_reverse_byte_order));

  size_t dlen = whmac_getlen(hd);
  if (*out_len < dlen) {
    memset(secret, 0, sizeof(secret));
    return false;
  }

  if (whmac_finalize(hd, out_hmac, dlen) < 0) {
    memset(secret, 0, sizeof(secret));
    return false;
  }
  *out_len = dlen;

  memset(secret, 0, sizeof(secret));
  return true;
}

bool get_hotp_buf(const char *secret, long counter, int digits, int algo,
                  char *out_buf, size_t out_len, cotp_error_t *err_code) {
  if (check_algo(algo) != 0 || check_otp_len(digits) != 0 || counter < 0) {
    *err_code = INVALID_USER_INPUT;
    return false;
  }

  whmac_handle_t *hd = whmac_gethandle(algo);
  if (!hd)
    return false;

  unsigned char hmac[64];
  size_t hlen = sizeof(hmac);
  if (!compute_hmac_buf(secret, counter, hd, hmac, &hlen)) {
    whmac_freehandle(hd);
    return false;
  }

  int tk = truncate(hmac, digits, hd);
  whmac_freehandle(hd);

  snprintf(out_buf, out_len, "%0*d", digits, tk);
  *err_code = NO_ERROR;
  return true;
}

bool get_totp_at_buf(const char *secret, long time, int digits, int period,
                     int algo, char *out_buf, size_t out_len,
                     cotp_error_t *err_code) {
  if (check_period(period) != 0) {
    *err_code = INVALID_PERIOD;
    return false;
  }
  return get_hotp_buf(secret, time / period, digits, algo, out_buf, out_len,
                      err_code);
}

// Legacy wrappers (will fail if called in secure world without heap, but
// provided for compatibility)
char *get_hotp(const char *secret, long counter, int digits, int algo,
               cotp_error_t *err_code) {
  return NULL;
}
char *get_totp_at(const char *secret, long time, int digits, int period,
                  int algo, cotp_error_t *err_code) {
  return NULL;
}
char *base32_encode(const unsigned char *user_data, size_t data_len,
                    cotp_error_t *err_code) {
  return NULL;
}
unsigned char *base32_decode(const char *user_data, size_t data_len,
                             cotp_error_t *err_code) {
  return NULL;
}
