#pragma once

/*
 * The usage is exactly the same as djb's code (as described at http://cr.yp.to/ecdh.html)
 * except that the function is called `curve25519\_donna`.
 *
 * To generate a private key, generate 32 random bytes and:
 *
 * ```
 * mysecret[0] &= 248;
 * mysecret[31] &= 127;
 * mysecret[31] |= 64;
 * ```
 *
 * To generate the public key, just do:
 *
 * ```
 * static const uint8_t basepoint[32] = {9};
 * curve25519_donna(mypublic, mysecret, basepoint);
 * ```
 *
 * To generate a shared key do:
 *
 * ```
 * uint8_t shared_key[32];
 * curve25519_donna(shared_key, mysecret, theirpublic);
 * ```
 *
 * And hash the `shared\_key` with a cryptographic hash function before using.
 */

int curve25519_donna(uint8_t *out, const uint8_t *my_secret, const uint8_t *basepoint);