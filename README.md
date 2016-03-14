# Elipzer-File-Encrypter
A simple file encryption program that allows for files to be encrypted using a simple password

I created this because of someone hinting that they needed some sort of encryption program. I cannot guerentee any amount of security since I have not tested it against anything.

I used an algorithm that essentially scrambles up the bits in groups of four bytes and if there are any trailing bytes, they are scrambled up in the groups that they need to be whether that is 1, 2, or 3.

Feel free to look over my code to see if you can come up with any improvements or changes that you think that could be made to the program to make it better.

To use the file, you have to use command line arguments to specify the file that you would like to encrypt or decrypt.

The program will detect whether it is encrypting or decrypting by the file extension.

THERE IS NO WARNING FOR OVERWRITING FILES SO WATCH OUT BEFORE YOU ACCIDENTALLY ENCRYPT SOMETHING AND DECRYPT IT WITH THE WRONG PASSWORD AND ARE NOT ABLE TO GET IT BACK.
