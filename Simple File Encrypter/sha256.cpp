#include <vector>
#include <iostream>
#include "sha256.h"

int Message::init(const std::vector<unsigned char>& bytes)
{
	//Bytes not correct size
	if (bytes.size() % 64 != 0)
		return -1;

	blocks.reserve(bytes.size() / 64);

	for (unsigned int i = 0; i < bytes.size() / 64; i++)
	{
		blocks.push_back(MessageBlock((unsigned char*)(bytes.data() + i * 64)));
	}

	return 0;
}

unsigned int Message::getMessageBlockCount() const
{
	return (unsigned int)blocks.size();
}

const MessageBlock& Message::getMessageBlock(unsigned int i) const
{
	return blocks[i];
}

MessageSchedule::MessageSchedule(Message m, uint32_t i)
{
	//64 32-bit words = 2048
	//First 16 are Mt(i)
	for (unsigned int t = 0; t < 16; t++)
		data[t] = MessageWord(m.getMessageBlock(i).getWord(t).getData());
	//17-64 are o1(Wt-2) + Wt-7 + 0(Wt-15) + Wt-16
	for (unsigned int t = 16; t < 64; t++)
		data[t] = MessageWord(
			o1(data[t - 2].getData()) +
			data[t - 7].getData() +
			o0(data[t - 15].getData()) +
			data[t - 16].getData()
			);
}

std::string sha256(std::string input)
{
	//Initial Hash Values
	uint32_t h[] = {
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19,
	};

	//Round Constants
	uint32_t k[] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	};

	//Copy input to a vector of chars
	std::vector<unsigned char> message(input.begin(), input.end());

	//Append bit "1" to message

	//This algorithm also automagically adds 7 "0"s to the message (after the 1 bit) because it is working with bytes
	//and not bits. (This will never be a problem as all unsigned chars are bytes)
	unsigned char firstBit(0x80);
	message.push_back(firstBit);

	//Make the message's size % 64 = 56  by adding chars.
	uint32_t sizeMod64 = message.size() % 64;
	uint32_t extraToAdd;
	if (sizeMod64 > 56)
		extraToAdd = 120 - sizeMod64;// (Amount to Add to get to Next Block + 56) = (64 - sizeMod64 + 56) = (120 - sizeMod64)
	else
		extraToAdd = 56 - sizeMod64;
	
	//Insert the zeros.
	message.resize(message.size() + extraToAdd);

	//Create an array of bytes that will be the size
	byte sizeArr[8];
	unsigned long long size = input.size() * 8;
	
	//Convert the long long size into bytes
	for (uint32_t i = 0; i < 8; i++)
		sizeArr[7 - i] = (byte)(size >> (i * 8));

	//Insert the size bytes into the message.
	message.insert(message.end(), sizeArr, sizeArr + 8);

	//Create the message
	Message mess;
	int err = mess.init(message);

	//Check for errors with the message calculation (Only checks for if it is for some reason
	//(which should never exist) that the message is the wrong length)
	if (err != 0)
	{
		std::cout << "Invalid Message" << std::endl;
		return "Invalid Message";
	}

	//Compute Hash
	for (uint32_t i = 0; i < mess.getMessageBlockCount(); i++)
	{
		//Create a temporary variable, h_tmp with values equal to m_h 
		uint32_t h_tmp[8];
		for (unsigned int i = 0; i < 8; i++)
			h_tmp[i] = h[i];

		//Create the Message Schedule
		MessageSchedule W(mess, i);

		//Compute the values to be added to the hash
		for (unsigned int t = 0; t < 64; t++)
		{
			uint32_t t1 = h_tmp[7] + E1(h_tmp[4]) + Ch(h_tmp[4], h_tmp[5], h_tmp[6]) + k[t] + W.getWord(t).getData();
			uint32_t t2 = E0(h_tmp[0]) + Maj(h_tmp[0], h_tmp[1], h_tmp[2]);
			h_tmp[7] = h_tmp[6];
			h_tmp[6] = h_tmp[5];
			h_tmp[5] = h_tmp[4];
			h_tmp[4] = h_tmp[3] + t1;
			h_tmp[3] = h_tmp[2];
			h_tmp[2] = h_tmp[1];
			h_tmp[1] = h_tmp[0];
			h_tmp[0] = t1 + t2;
		}

		//Create the next version of the hash
		for (unsigned int i = 0; i < 8; i++)
		{
			h[i] = h_tmp[i] + h[i];
		}
	}

	//Create Digest
	byte digest[32];

	//Put the values into the digest.
	for (unsigned int i = 0; i < 8; i++)
	{
		UINT32_T_TO_BYTE_ARRAY(h[i], digest + i * 4);
	}

	//Convert h to a string
	//32 for digest size, 2 chars per digest byte (0xXX), 1 for null termination at end ('\0')
	char buf[65];
	buf[64] = '\0';

	for (unsigned int i = 0; i < 32; i++)
		sprintf_s(buf + i * 2, 3, "%02x", digest[i]);

	//Return the Computed Hash String (In hexadecimal)
	return std::string(buf);
}