# Elipzer-File-Encrypter
A simple file encryption program that allows for files to be encrypted using a simple password

I created this because of someone hinting that they needed some sort of encryption program. I cannot guerentee any amount of security since I have not tested it against anything.

I used an algorithm that essentially scrambles up the bits in groups of four bytes and if there are any trailing bytes, they are scrambled up in the groups that they need to be whether that is 1, 2, or 3.

Feel free to look over my code to see if you can come up with any improvements or changes that you think that could be made to the program to make it better.

To use the file, you have to use command line arguments to specify the file that you would like to encrypt or decrypt.

The program will detect whether it is encrypting or decrypting by the file extension.

THERE IS NO WARNING FOR OVERWRITING FILES SO WATCH OUT BEFORE YOU ACCIDENTALLY ENCRYPT SOMETHING AND DECRYPT IT WITH THE WRONG PASSWORD AND ARE NOT ABLE TO GET IT BACK.

Here's how it works:

The Algorithm is as follows:

Password > SHA-256 Hash

First the password is converted into a SHA-256 Hash Value.

Encryption

Hash > Move Key

The current hash value is set to the SHA-256 of its string value.

The new hash value is used to generate a "MoveKey"

A MoveKey is a map where the key is the index of the source bit and the value is the index of the target bit.

MoveKey Used to Scramble

The MoveKey is used to scramble the bytes in 4 byte blocks. (If there are not enough bytes for a 4 byte block, a move key can be generated for 3, 2, or 1 byte blocks as well)

The reason that 4 byte blocks are used is that a SHA-256 hash as a string has the ability to create up to 32 numbers from 0x00 to 0xFF if you split the string into 2 char segments.

For Example, the SHA-256 of "test"

    9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
Creates the values or digestints,

    0x9f 0x86 0xd0 0x81 0x88 0x4c 0x7d 0x65
    0x9a 0x2f 0xea 0xa0 0xc5 0x5a 0xd0 0x15
    0xa3 0xbf 0x4f 0x1b 0x2b 0x0b 0x82 0x2c
    0xd1 0x5d 0x6c 0x15 0xb0 0xf0 0x0a 0x08
These values then can be converted into indices for the MoveKey map by using the range of numbers from 0-31 inclusive to find the mapped values using the algorithm as follows:

Create "DigestInts" with algorithm above

Create Array "slots" with values 0-31 inclusive

Create Array "MoveKey" with no values

Loop from i = (0 - 31) inclusive doing:

Set Temporary "slotindex" to the value of ("DigestInts" at i) modulo the size of slots

Set Temporary "slotvalue" to the value of ("slots" at "slotindex")

Remove the value at "slotindex" from slots

Append the value "slotvalue" to "MoveKey"

end Loop

Pseudo Code:

slots = [0, 1, 2, 3, 4, ... , 31];
for (int i = 0; i < 32; i++) {
    unsigned char slotindex = digestints[i] % slots.size();
    unsigned char slotValue = slots[slotindex];
    slots.removeAt(slotindex);
    movekey.push(slotValue);
}
At the end of this process, the move key will be an array of 32 integers from 0 - 31 inclusive.

MoveKey > Map Bytes

The actual "scrambling" or more so "mapping" takes place by using the generated MoveKey array and using it to move the initial "not-encrypted" bytes to their new "encrypted" locations.

As explained previously, the MoveKey is essentially a map for the bytes. The first byte will be mapped in the new block to the position at MoveKey[0]

For Example the following MoveKey:

[
    18, 06, 03, 17, 15, 21, 09, 25,
    22, 16, 07, 23, 31, 24, 26, 20, 
    04, 29, 14, 30, 02, 12, 11, 27, 
    01, 13, 00, 19, 28, 10, 08, 05
]
And the bytes of a UTF-8 String, "test":

    t: 0 1 1 1 0 1 0 0
    e: 0 1 1 0 0 1 0 1
    s: 0 1 1 1 0 0 1 1
    t: 0 1 1 1 0 1 0 0
Would produce the following "Scrambling" of Bytes:

    1 0 0 1 0 0 1 1
    0 0 1 1 0 0 1 1
    1 1 0 1 1 1 0 0
    1 0 0 1 0 1 1 0
Which cannot be represented in UTF-8

A specific mapping example in this would be that the 4th bit in the decrypted block (1) is mapped to the 18th bit in the encrypted block.

Repeat

Repeating this process (From Hash > MoveKey > Map Bytes) Allows for Unlimited numbers of MoveKeys to be generated and files of an unlimited size to have their bytes "scrambled" or more so "remapped"

Decryption

Now that you understand how the encryption works, decryption is fairly simple, it is the opposite of encryption. Instead of mapping the bits from their indices to new encrypted locations using the move key, you can use the indices of the values in the MoveKey as the destination bit indices and the values in the MoveKey as the indices of the encrypted bits.

Using this, the scrambled bytes:

    1 0 0 1 0 0 1 1
    0 0 1 1 0 0 1 1
    1 1 0 1 1 1 0 0
    1 0 0 1 0 1 1 0
can be mapped to the string "test":

    t: 0 1 1 1 0 1 0 0
    e: 0 1 1 0 0 1 0 1
    s: 0 1 1 1 0 0 1 1
    t: 0 1 1 1 0 1 0 0
using the MoveKey:

[
    18, 06, 03, 17, 15, 21, 09, 25,
    22, 16, 07, 23, 31, 24, 26, 20, 
    04, 29, 14, 30, 02, 12, 11, 27, 
    01, 13, 00, 19, 28, 10, 08, 05
]
You can convert the MoveKey into an InverseMoveKey if you would like using this algorithm:

Create Array "InverseKey" containing 32 0s

Use "MoveKey" from above

Loop from i = (0 - 31) inclusive doing:

Set InverseKey at (MoveKey at i) to i

end Loop

Pseudo Code:

inversekey = [0, 0, 0, 0, 0, ... , 0];//32 0s
movekey = [MOVEKEY];
for (int i = 0; i < 32; i++) {
    inversekey[movekey[i]] = i;
}
You could use the InverseMoveKey to do the same mapping on the encrypted bits to get the decrypted bits if you would so like to.

Simplified Version (AKA: TL;DR)

Create MoveKey from Password
Map bytes in four byte blocks to new positions using MoveKey
Create New MoveKey from Hash and repeat.
Decrypt by using the inverse of the movekey to map the encrypted blocks to the decrypted positions.
Personally I like to call the algorithm the "Steaming Soup" algorithm because when you draw lines from the decrypted bits to the encrypted bits, it looks similar to steam coming off a cup of hot liquid.

I could not break this encryption myself but as Schneier says, "Anyone, from the most clueless amateur to the best cryptographer, can create an algorithm that he himself can't break." (Schneier's Law)

There are some special cases where this encryption fails and those include the following:

When the bytes being encrypted are all 0 or all 1, this algorithm will do nothing to the bytes.

When the bytes being encrypted have sparse changes i.e. one 1 per 100 0s, the encryption may have blocks equal to the decrypted blocks.
