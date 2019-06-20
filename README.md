# NEMESIS-rewrite
Pet project of mine where I create a new cryptosystem (polyalphabetic substitution on a byte level). Done on my 3rd year of my Math's degree. NEMESIS works by having two passwords that are combined to create a very long keystream to encode each individual byte. This is the more recent Cython version.

### NEMESIS Cipher
----------------------------------------------------------
**Brief explanation on how it works**

Given two keys (Key1 and Key2 - with lengths L1 and L2), we store each of them in the first row of a tringular matrix with size L1 and L2 respectively. All new rows of each matrix are then filled with random characters, extrapolated from the characters of Key1 and Key2 applying multiplication and addition modulo 256. Given large enough keys, the entropy given by all characters of both keys is enough to produce strong pseudo-random characters.

Each byte of data is then encrypted using both matrices, which are the keystreams. The result is a double keystream cipher, with Keystream1 and Keystream2 of length LCM(1,...,L1)=LCM(1,...,L1/2) and LCM(1,...,L2)=LCM(1,...,L2/2) each, functions that quickly rise to infinity (approx. 2.65^n). This allows to use 2 relatively short passphrases as the main security device of the cipher.

----------------------------------------------------------
**Security of the cipher**

We consider a character alphabet consisting of just letters (both upper and lower case), numbers and whitespaces to be used for keys (in reality, a lot more characters can be used). Given an approximation of 64 to those 63, we have that the security in bits of the cryptosystem in a brute force attack is 2^b = 64^(L1+L2). This gives us the following formula:

b = log_2(64)·(L1+L2) = 6·(L1+L2)    ==>    132-bit security = two keys that are each 11 characters long

Of course, given the nature of this cipher, smaller files need pretty larger keys than necessary to ensure security, but on the other hand, large files are easier to protect. Several files have been encrypted using the NEMESIS cipher and then subjected to randomness tests. All files seem to pass the tests on the DIEHARD and NIST suites.

----------------------------------------------------------
**Potential attacks on NEMESIS**

This cipher is as of yet unknown, and the author's lack of knowledge makes it rather difficult to back any claims concerning cryptanalysis of the cipher. The only claim that can be made has already been made (passes RNG test suites).

----------------------------------------------------------
**Explaining the encryption algorithm**

In encryption, each byte is encoded by using both keystreams. Each byte is multiplied by a random odd integer factor called RK based on the sum of both keystream's current character, then added Keystream1 and substracted Keystream2. Then, the result is yet again multiplied by another random odd integer factor. Decryption follows the revese approach, which is easy to do since odd integers are multiplication-invertible modulo 256. This is process is called RK+ encryption/decryption.

This prevents a user with knowledge of the message (but who doesn't know the keys) to recover the keys, since both keystreams are used for each byte thrice, once on an addition of unkown value, and twice again on a multiplication. It's the multiplication that throws away any hope of altering the message without knowledge of the keys. Any change to the ciphertext without knowing the keys results in an unpredicted character during decryption.

----------------------------------------------------------
**Message Authentication Code**

Upon ending RK+ decryption/encryption, a MAC is given based on the resulting ciphertext. If 2 MACs belonging to the same file don't match using the same keys, then the file has been tampered with after encryption.

The probability of editing an encrypted file and getting the same MAC is 1 in 3 billion (3,368,562,317 to be exact), since a checksum (CS) of the ciphertext is made, and then CS is returned modulo 251, 241, 239 and 233 (all primes). The usage of the MAC warns of message corruption, and further prevents/discourages file tampering.
