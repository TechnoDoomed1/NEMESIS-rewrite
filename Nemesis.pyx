#--------------------------------------------------------------------------------
# [N E M E S I S] Cipher
#--------------------------------------------------------------------------------
# >> HOW IT WORKS
#--------------------------------------------------------------------------------
# Given two keys (key1 and key2 - with lengths L1 and L2), we store each of them
# in the first row of a tringular matrix with size L1 and L2 respectively. All
# new rows of each matrix are then filled with random characters, extrapolated
# from the characters of Key1 and Key2. Given large enough keys, the entropy
# given by all characters of both keys is enough to produce strong randomization.
#
# Each byte of data is then encrypted using both matrices, which are the key-
# streams. The result is a 2x keystream cipher, with Keystream1 and Keystream2
# of length LCM(1,...,L1)=LCM(1,...,L1/2) and LCM(1,...,L2)=LCM(1,...,L2/2) each,
# functions that quickly rise to infinity (approx. 2.65^n). This allows us to use
# 2 relatively short passphrases as the main security device of the cipher.
#
#--------------------------------------------------------------------------------
# >> SECURITY
#--------------------------------------------------------------------------------
# We consider a character alphabet consisting of just letters (both upper and
# lower case), numbers and whitespaces to be used for keys (in reality, a lot
# more characters can be used). Given an approximation of 64 to those 63 chars,
# we have that the security in bits of the cryptosystem in a brute force attack
# is 2^b = 64^(L1+L2). This gives us the following formula:
#
#       b = log_2(64)·(L1+L2) = 6·(L1+L2)    ==>    132-bit security =
#                                                          = two 11-char keys
#
# Of course, given the nature of this cipher, smaller files need pretty larger
# keys than necessary to ensure security, but on the other hand, large files
# are easier to protect. Several files have been encrypted using the NEMESIS
# cipher and then subjected to randomness tests. All files pass the DIEHARD and 
# NIST test suites.
#
#--------------------------------------------------------------------------------
# >> POTENTIAL WEAKNESSES
#--------------------------------------------------------------------------------
# This cipher is as of yet unknown, and the author's lack of knowledge makes
# it rather difficult to back any claims concerning cryptanalysis of the
# cipher. The only claim that can be made is that it passes RNG test suites, and
# that several cryptographic attacks using brute force, linear and differential
# cryptoanalysis have executed, without being able to break encryption.
#
#--------------------------------------------------------------------------------
# >> ENCRYPTION ALGORITHM
#--------------------------------------------------------------------------------
# In encryption, each byte is encoded by using both keystreams. Each byte is
# multiplied by a random odd integer factor based on the sum of both keystreams
# and then added keystream1 and substracted keystream2. Then, the result is yet
# again multiplied by another random odd integer. 
# This process has been named as RK+.
#
# Decryption follows the reverse scheme, which is easy to do since odd integers
# are invertible modulo 256.
#
# The approach of this cipher prevents a user with knowledge of the message to
# recover the keys, since both keystreams are used for each byte 3 times: once
# in addition/substraction, and twice on multiplication. It's precisely the
# multiplication part that throws away any hope of altering the message without
# knowledge of the keys, since changes in the ciphertext results in highly
# unpredictable characters during decryption.
#
#--------------------------------------------------------------------------------
# >> MESSAGE AUTHENTICATION CODE
#--------------------------------------------------------------------------------
# Upon ending the RK+ encryption/decryption algorithm, a MAC is given based on
# the resulting ciphertext. If 2 MACs belonging to the same file don't match
# using the same keys, then file has either been damaged or tampered with.
#
# The probability of editing an encrypted byte and getting the same MAC is 1
# in 3 thousand million (3,368,562,317 to be exact), since a checksum of the
# ciphertext is made, and then returned modulo 251, 241, 239 and 233 (all of 
# them prime numbers).
#
#================================================================================
import cython
import sys

cdef int _ODD[128]
cdef int _INVERSE[128]

_ODD[:] = range(1, 256, 2)
_INVERSE[:] = [1, 171, 205, 183, 57, 163, 197, 239, 241, 27, 61, 167, 41, 19,
               53, 223, 225, 139, 173, 151, 25, 131, 165, 207, 209, 251, 29,
               135, 9, 243, 21, 191, 193, 107, 141, 119, 249, 99, 133, 175,
               177, 219, 253, 103, 233, 211, 245, 159, 161, 75, 109, 87, 217,
               67, 101, 143, 145, 187, 221, 71, 201, 179, 213, 127, 129, 43,
               77, 55, 185, 35, 69, 111, 113, 155, 189, 39, 169, 147, 181, 95,
               97, 11, 45, 23, 153, 3, 37, 79, 81, 123, 157, 7, 137, 115, 149,
               63, 65, 235, 13, 247, 121, 227, 5, 47, 49, 91, 125, 231, 105,
               83, 117, 31, 33, 203, 237, 215, 89, 195, 229, 15, 17, 59, 93,
               199, 73, 51, 85, 255]


# DECORATOR: Runs a function when the module is run. Makes no other change
# to the function.
def execute_on_run (function):
    if __name__ == "__main__":
        function()
        
    return function


# STRING TO BYTE SEQUENCE: Translates an string to a byte sequence using
# the utf-8 encoding. Implemented as a numpy array because its faster.
def as_bytes (x):
    return bytearray(x, encoding='UTF-8')


# NECESSARY_LENGTH: Returns the necessary length that a key must have to
# allow a secure encryption. It depends on LCM(1,...,n) = LCM(n/2,...,n)
# which follows assimptotically 2.65^n
cdef int necessary_length (int size):
    cdef int k = 2
    cdef double approx_growth_rate = 2.65

    while(approx_growth_rate < size):
        k += 1
        approx_growth_rate *= 2.65

    return k

#--------------------------------------------------------------------------------
# KEYSTREAM GENERATION: Generates the keystreams applying a pseudo-random
# operations of the characters of key1 and key2.

def generate_keystreams (key1, key2):
    from math import ceil

    # Extract the corresponding lengths of each key, and also store their
    # rounded up halves.
    cdef int L1 = len(key1)
    cdef int L2 = len(key2)
    cdef int stop1 = int(ceil(L1 / 2))
    cdef int stop2 = int(ceil(L2 / 2))
    cdef int i, j, k, aux

    # The keystreams are "matrices" (implemented as a list of byte sequences
    # of decreasing size). The first "row" is the original key.
    keystream1, keystream2 = [as_bytes(key1)], [as_bytes(key2)]

    # Now we populate each keystream with new pseudo-random byte sequences,
    # each with 1 less byte than its precedessor. We stop when we hit Lx/2
    # (rounded up) where x is either 1 or 2.

    # --- Creating keystream1 ---
    for i in range(1, 1 + stop1):
        keystream1.append([]) # Start as an empty list, so it can be extended.
        j = 0
        while(j < L1 - i):
            aux = keystream1[-2][j] * keystream1[-2][L1-i]
            aux += keystream1[-2][j+1] * keystream1[-2][min(0, j-1)]

            for k in range(L2):
                aux += (keystream2[0][k] * keystream2[0][(k + j) % L2] *
                        keystream1[0][(aux + k) % L1])

            keystream1[-1].append(aux % 256)
            j += 1
            
        # At the end, convert into a byte sequence.
        keystream1[-1] = bytearray(keystream1[-1])


    # --- Creating keystream2 ---
    for i in range(1, 1 + stop2):
        keystream2.append([]) # Start as an empty list, so it can be extended.
        j = 0
        while(j < L2 - i):
            aux = keystream2[-2][j] * keystream2[-2][L2-i]
            aux += keystream2[-2][j+1] * keystream2[-2][min(0, j-1)]

            for k in range(L1):
                aux += (keystream1[0][k] * keystream1[0][(k + j) % L1] *
                        keystream2[0][(aux + k) % L2])

            keystream2[-1].append(aux % 256)
            j += 1

        # At the end, convert into a byte sequence.
        keystream2[-1] = bytearray(keystream2[-1])

    
    # Return both keystreams.
    return (keystream1, keystream2)
#--------------------------------------------------------------------------------
#--------------------------------------------------------------------------------
# ENCRYPTION ALGORITHM: Performs encryption on the given file.
# Since we tested that the file exists and that we have permission to use it,
# we are not going to catch exceptions here. If they are raised, the program
# will simply tell the user and exit forcefully afterwards.

@cython.boundscheck(False)
@cython.cdivision(True)
def nemesis_encrypt (filename):
    from math import ceil

    # We convert the variables that are going to be used in the encryption
    # loop to C types so that the loop is much faster. Typed memory views are
    # used to access the underlying C buffer for array structures.
    cdef int L1, L2, stop1, stop2, minlen, index, byte1, byte2, RK, i
    cdef long long size, checksum, count
    cdef char[:] data_view

    try:
        from os import stat

        # Ask the user to give us the keys.
        size = stat(filename).st_size
        minlen = necessary_length(size)
        
        print("Introduce a 1st password at least", minlen, "characters long:")
        while True:
            key1 = input('')
            if len(key1) >= minlen: break

        print("Introduce a 2nd password at least", minlen, "characters long:")
        while True:
            key2 = input('')
            if len(key2) >= minlen: break
        

        # Generate the keystreams from the given keys.
        keystream1, keystream2 = generate_keystreams(key1, key2)

        # Print the cipher's security in bits.
        print("Bits used for encoding:", 6*(len(key1) + len(key2)))

        # Delete variables which are not going to be used again to recover
        # some memory. Statically typed variables may not be deleted.
        del key1, key2

        print("Keystream generation did go well.")

        # Perform the actual encryption over the data. For that, open the
        # file again and overwrite its contents.
        with open(filename, 'r+b') as datafile:
            
            # Variable initilizations.
            L1, L2 = len(keystream1[0]), len(keystream2[0])
            stop1 = int(ceil(L1 / 2))
            stop2 = int(ceil(L2 / 2))
            count, checksum = 0, 0


            # Read chunks of 1048576 bytes (1 Mb) each time from the file.
            data = bytearray(datafile.read(1048576))
            data_view = data
            
            while(count < size):
                # The bytes coming through the 2 keystreams.
                byte1, byte2 = 0, 0

                # Accumulate all the repeating bytes in each "row" of each
                # keystream. This is the foundation of the cipher, and the
                # reason we generated a keystream from each key.
                for i in range(stop1): byte1 += keystream1[i][count %(L1 - i)]
                for i in range(stop2): byte2 += keystream2[i][count %(L2 - i)]
                byte1 %= 256
                byte2 %= 256
                
                # Now we calculate the RK factors, and encrypt the original
                # byte from 'data'.
                RK = ((byte1 + byte2)%256)//2
                index = count % 1048576
                
                RK = (((_ODD[RK] * data_view[index]) + byte1 - byte2)
                      *_ODD[127-RK]) % 256

                data_view[index] = RK

                # Update the checksum and count variables.
                checksum += data_view[index]
                count += 1

                # Once we have exhausted our chunk of 1024 bytes, overwrite
                # the original and get a new one.
                if count % 1048576 == 0:
                    position = count - 1048576
                    datafile.seek(position)
                    
                    datafile.write(data)
                    data = bytearray(datafile.read(1048576))
                    data_view = data
                    
                    print("%d Megabytes processed" % (count // 1048576))


        # ENSURE THAT THE LAST READ CHUNK IS PROCESSED AND WRITTEN!!!

        # Encryption is finished. Print the MAC on-screen.
        print("Message Authentication Code: %03d-%03d-%03d-%03d" %
              (checksum % 233, checksum % 239, checksum % 241, checksum % 251))

        # Remove non-typed variables to free memory.
        del data

        
    except:
        raise
        print("ERROR: A fatal error occurred. Press ENTER to exit.")
        input("")
        sys.exit(1)
        
#--------------------------------------------------------------------------------
#--------------------------------------------------------------------------------
def nemesis_decrypt (filename):
    pass

#--------------------------------------------------------------------------------
#--------------------------------------------------------------------------------
# MAIN FUNCTION: This is what the user sees when the module is run.
# Since this module is supposed to be packaged into an executable binary file,
# this will be the module's interface with the user.

@execute_on_run
def main ():
    # Dictionary that maps the input to the corresponding function.
    usage_modes = {'encrypt': nemesis_encrypt,
                   'decrypt': nemesis_decrypt}

    print("===============================================================")
    print("   N E M E S I S   ")

    # Ask the user for input.
    while True:
        print("===============================================================")
        print("Accepted commands: [optional_filename] -decrypt -encrypt -quit")
        x = input(">> ")

        try:
            # Parse the input to get the filename and the parameters.
            x = x.split(' -')
            # If the "-quit" parameter was passed, exit immediately.
            if(('-quit' in x) or ('quit' in x)): sys.exit(0)
            # Otherwise, try to assign the data. If a ValueError is raised...
            filename, mode = x

        # The assignment (filename, mode) failed.
        except ValueError:
            print("ERROR: Incorrent syntax.", end='')
            mode = ''
            filename = ''

            # The user tried to encrypt and decrypt at the same time.
            # That obviously is stupid.
            if ('decrypt' in x) and ('encrypt' in x):
                print("You can't encrypt & decrypt at the same time.")
                
            # The user didn't form a coherent command.
            else:
                print("Failure to specify either file or mode.")

        # An unknown exception was raised.
        # We don't know how to handle it, so exit the program forcefully.
        except:
            raise
            print("ERROR: A fatal error occurred. Press ENTER to exit.")
            input("")
            sys.exit(1)

        finally:
            try:
                # Verify that the file exists.
                f = open(filename, 'r')
                f.close()

            except (NameError, FileNotFoundError):
                # The file doesn't exist. Stop user from trying a mode.
                print("ERROR: File does not exist or input was incorrect.\n")
                mode=''

            except PermissionError:
                # The file can't be used. Stop user from trying a mode.
                print("ERROR: Could not open the specified file.\n")
                mode=''
                
            finally:
                # Execute the appropiate mode. Otherwise, do nothing.
                usage_modes.get(mode, lambda x: None)(filename)
