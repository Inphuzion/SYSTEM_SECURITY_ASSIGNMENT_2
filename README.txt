ECDH and RSA Assignment

AM1: 2022030039 AM2: 2022030172

The AM utilized is AM1


ecdh_assign_2
-------------
Performs an ECDH key exchange between Alice and Bob on Curve25519
using libsodium, and derives two keys from the result.

+ parse_scalar(): turns the -a/-b hex number into a 32-byte private
   key, written in reverse byte order. Without -a/-b, randombytes_buf()
   creates a random key.

+ crypto_scalarmult_base(): each side multiplies its private key with
   the base point to get its public key.

+ crypto_scalarmult(): each side combines its own private key with the
   other's public key; sodium_memcmp() confirms both results are
   identical.

+ crypto_generichash(): the shared secret and both public keys are
   placed in one 96-byte buffer and hashed (BLAKE2b) into the master key.

+ crypto_kdf_derive_from_key(): called twice on the master key (ids 1
   and 2) to get the Encryption and MAC keys, using the last 8 AM
   digits as context.

    ++Command used to produce ecdh_2022030039.txt:

    ./ecdh_assign_2 -n 2022030039 -o ecdh_2022030039.txt -a 0x2022030039 -b 0x9300302202


rsa_assign_2
------------
Uses GMP for all big-integer arithmetic and libsodium for SHA-256.
Generates key pairs, encrypts and decrypts files of any length, and
signs and verifies files.

+ generate_key(): creates a new key pair from two random primes and
   saves it to public_<length>.key and private_<length>.key.

+ load_key(): reads a key file and checks that it is valid.

+ make_frame(): puts a piece of the file into a fixed-size block.

+ check_frame(): checks that a decrypted block has the correct form and
   returns the length of the data inside it.

+ encrypt_buf(): splits the file into pieces, puts each piece in a
   block and encrypts it with the public key.

+ decrypt_buf(): decrypts each block with the private key, using the
   faster CRT method (rsa_private_crt()), and keeps only the data.

+ sign_buf(): hashes the file with SHA-256 and signs the hash with the
   private key.

+ verify_buf(): checks the signature with the public key and prints
   VALID or INVALID.

+ performance(): measures the time and memory of every operation for
   1024, 2048 and 4096-bit keys.

    ++Commands used to produce the result files:

    ./rsa_assign_2 -g 1024
    ./rsa_assign_2 -i am.txt -o am.sig -k private_1024.key -s
    ./rsa_assign_2 -a performance.txt -i perf_input.txt
