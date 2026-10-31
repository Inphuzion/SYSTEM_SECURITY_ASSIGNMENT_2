Files for the 2026 ECDH/RSA assignment. All files except the PDF were produced by our reference implementation. Do not modify them.
The PDF (section "Files in this package") explains what to do with each one and gives the exact self-check commands.

Assign2026.pdf              The assignment. Read it first.
ecdh_sample_2022123456.txt  Task 1. Expected output of ./ecdh_assign_2 -n 2022123456 -o out.txt -a 0x2022123456 -b 0x6543212202
public_2048.key             Task 2. Our RSA public key (2048 bits). Use with -k for -e and -v.
private_2048.key            Task 2. Our RSA private key (2048 bits, with p and q). Use with -k for -d and -s.
sample.txt                  Task 2. Plaintext, 512 bytes. Encrypting it must give sample.enc; signing it must give sample.sig.
sample.enc                  Task 2. sample.txt encrypted with public_2048.key (768 bytes). Decrypting it must give sample.txt.
sample.sig                  Task 2. Signature of sample.txt. Verification must print VALID.
sample_tampered1.sig        Task 2. Modified copy of sample.sig. Verification must print INVALID.
sample_tampered2.sig        Task 2. Modified copy of sample.sig. Verification must print INVALID.
challenge.enc               Task 2. Encrypted text. Decrypt it and quote the secret phrase in your report.
perf_input.txt              Task 2. Input for the performance analysis (-a). 2000 bytes.
