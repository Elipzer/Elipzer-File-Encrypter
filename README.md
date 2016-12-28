# Elipzer-File-Encrypter
A simple file encryption program that can encrypt any file using a simple password.

I created this because of someone hinting that they needed some sort of encryption program. I cannot guarantee any amount of security since I have not tested it against anything.

I used an algorithm that essentially scrambles up the bits in groups of four bytes and if there are any trailing bytes, they are scrambled up in the groups that they need to be whether that is 1, 2, or 3.

To use the file, you have to use command line arguments to specify the file that you would like to encrypt or decrypt.

The program will detect whether it is encrypting or decrypting based on the file extension.

THERE IS NO WARNING FOR OVERWRITING FILES SO WATCH OUT BEFORE YOU ACCIDENTALLY ENCRYPT SOMETHING AND DECRYPT IT WITH THE WRONG PASSWORD AND ARE NOT ABLE TO GET IT BACK.

Here's how it works.

To put it very simply, the program creates a key from the "password" that you supply and uses the key to remap the bytes inside of the target file thereby encrypting it. The reverse process can be used to decrypt the file.

Here's how the algorithm works:

#Encryption

First the password is converted into a SHA-256 hash.

Next, the hash is converted into a "Move Key"

A Move Key is the map that determines where to move each byte of the file for the next 4 byte block.

To generate the Move Key, the hash is split into 32 2-digit hexadecimal numbers.

Example:

SHA-256 of "test"

    9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

Split into 32 hexidecimal numbers:

    0x9f 0x86 0xd0 0x81 0x88 0x4c 0x7d 0x65
    0x9a 0x2f 0xea 0xa0 0xc5 0x5a 0xd0 0x15
    0xa3 0xbf 0x4f 0x1b 0x2b 0x0b 0x82 0x2c
    0xd1 0x5d 0x6c 0x15 0xb0 0xf0 0x0a 0x08

Then create a list of the integers from 0-31 inclusive. This list will be called slots.

Then, loop through each hexidecimal number from the Move Key and pop the value of slots at the index of the hexidecimal number modulo the length of slots into the next index of the Move Key.

Once this is finished, the Move Key will have 32 numbers from 0-31 that are "scrambled" based on the password.

Note that the Move Key is one-to-one on [0,31]

Example:
Using previous hexidecimal numbers, the generated Move Key would be

    [
        31, 10, 29, 14, 26, 24, 23, 01,
        12, 02, 19, 18, 27, 21, 15, 06,
        05, 22, 17, 03, 16, 00, 04, 30,
        08, 11, 07, 13, 09, 20, 25, 28
    ]

Pseudo Code For This Process:

    hexnumbers = [...]
    movekey = [];
    slots = [0, 1, 2, 3, 4, ... , 31];
    for (int i = 0; i < 32; i++) {
        unsigned char slotIndex = hexnumbers[i] % slots.size();
        unsigned char slotValue = slots[slotindex];
        slots.removeAt(slotIndex);
        movekey.push(slotValue);
    }

Next, take the values of each byte in the four byte block and map them to the encrypted four byte block using the Move Key as a map where the index of the Move Key is the index of the bit in the inBytes and the value at that index is the index of the bit in the outBytes.

Example:

Using the bytes of a UTF-8 String, "test":

    t: 0 1 1 1 0 1 0 0
    e: 0 1 1 0 0 1 0 1
    s: 0 1 1 1 0 0 1 1
    t: 0 1 1 1 0 1 0 0

And the Move Key (Note: NOT from previous example)

    [
        18, 06, 03, 17, 15, 21, 09, 25,
        22, 16, 07, 23, 31, 24, 26, 20, 
        04, 29, 14, 30, 02, 12, 11, 27, 
        01, 13, 00, 19, 28, 10, 08, 05
    ]

The bytes in "test" get mapped to this:

    1 0 0 1 0 0 1 1
    0 0 1 1 0 0 1 1
    1 1 0 1 1 1 0 0
    1 0 0 1 0 1 1 0

Pseudo Code:

    bool[32] inBytes = [...];
	bool[32] outBytes;
	for (int i = 0; i < 32; i++) {
		outBytes[movekey[i]] = inBytes[i];
	}
   

The first byte in the test string is mapped to the 19th byte in the output, the second to the 7th, and so on.

This process is repeated until the end of the file is reached.

Note that a new hash is generated from the SHA-256 of the previous hash to generate a new, unique Move Key on each pass.

If the file does not have bytes that are a multiple of four, a Move Key for only 1, 2, or 3 bytes can be substituted for the 4 byte Move Key.

#Decryption

Decryption is similar to encryption except it uses the inverse Move Key.

Since the Move Key is one-to-one on [0-31], the "inverse" version of it can be calculated by taking where each index was mapped to and using that as the index to map from and the index as where to map to. This is similar to finding the f^-1 for f.

Example:

Using the same Move Key as in the previous example

    [
        18, 06, 03, 17, 15, 21, 09, 25,
        22, 16, 07, 23, 31, 24, 26, 20, 
        04, 29, 14, 30, 02, 12, 11, 27, 
        01, 13, 00, 19, 28, 10, 08, 05
    ]

Its inverse can be calculated and it is 

    [
        26, 24, 20, 02, 16, 31, 01, 10,
        30, 06, 29, 22, 21, 25, 18, 04,
        09, 03, 00, 27, 15, 05, 08, 11,
        13, 07, 14, 23, 28, 17, 19, 12
    ]

Then simply use the "inverse" Move Key in the same way that was done with the "regular" Move Key but on the encrypted bytes

Example:

Using the inverse Move Key as calculated before and encrypted version of "test"

    1 0 0 1 0 0 1 1
    0 0 1 1 0 0 1 1
    1 1 0 1 1 1 0 0
    1 0 0 1 0 1 1 0

Then gets mapped back to

    0 1 1 1 0 1 0 0
    0 1 1 0 0 1 0 1
    0 1 1 1 0 0 1 1
    0 1 1 1 0 1 0 0

Which is the same as "test" and thus the algorithm worked.

    t: 0 1 1 1 0 1 0 0
    e: 0 1 1 0 0 1 0 1
    s: 0 1 1 1 0 0 1 1
    t: 0 1 1 1 0 1 0 0

This can be repeated in the same way as the encryption algorithm for files of any size by creating new hashes and more "inverse" Move Keys as needed.

$Simplified Version (AKA TL;DR)

Create Move Key from Password
Map bytes in four byte blocks to new positions using Move Key
Create New MoveKey from Hash and repeat.
Decrypt by using the inverse of the Move Key to map the encrypted blocks back to their decrypted positions.

I find my algorithm interesting because the encrypted file is always the exact same length as the encrypted file.

I could not break this encryption myself but as Schneier says, "Anyone, from the most clueless amateur to the best cryptographer, can create an algorithm that he himself can't break." (Schneier's Law)

#Shortcomings

There are some shortcomings where my algorithm fails including the following cases:

When the bytes being encrypted are all 0 or all 1, this algorithm will do nothing to the bytes as it just remaps them.

When the bytes being encrypted have sparse changes (i.e. one 1 per 127 0s), the encryption may have blocks equal to the decrypted blocks for the same reason as the previous.

These problems are caused by the fact that in this algorithm, the output bytes have the exact same number of 1 and 0 bits as the input bytes.

A workaround to both of these would be to add an extra fifth byte per each four byte block with "randomly" filled bits as extra data for each runthrough of a Move Key. In this case, the Move Key would move the original four bytes to an output of five bytes and then the rest of the bits that were not set by the move key would be set to random values. The trouble with this workaround is that the output file would be 1.25x as large as the input file.

#Other Thoughts

The mapping by blocks method works well but could be changed to be mapping by the whole file. In this case, a Move Key would map each bit of the file to a new location in the output file rather than doing it four bytes at a time. In this way, a bit from the beginning of the file could be moved to any place in the file rather than just the first four bytes of it.
