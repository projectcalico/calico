#include <openssl/err.h>
#include <openssl/fips.h>
#include <openssl/ssl.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  fprintf(stderr, "Startup\n");

  if (FIPS_mode()) {
    fprintf(stderr, "FIPS mode already set.\n");
  } else {
    fprintf(stderr, "Not to set FIPS mode...\n");
  }

  fprintf(stderr, "Attempt FIPS self tests...\n");

  if (FIPS_selftest()) {
    fprintf(stderr, "FIPS self tests succeeded.\n");
  } else {
    fprintf(stderr, "ERROR: FIPS self tests failed.\n");
    ERR_print_errors_fp(stderr);
  }

  return 0;
}
