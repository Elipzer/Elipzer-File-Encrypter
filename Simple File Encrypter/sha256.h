#pragma once

#include <string>

typedef unsigned char byte;

#define ROTR(x, y) ((x >> y) | (x << ((sizeof(x) << 3) - y)))
#define ROTL(x, y) ((x << y) | (x >> ((sizeof(x) << 3) - y)))

#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define E0(x) ((ROTR(x, 2)) ^ (ROTR(x, 13)) ^ (ROTR(x, 22)))
#define E1(x) ((ROTR(x, 6)) ^ (ROTR(x, 11)) ^ (ROTR(x, 25)))
#define o0(x) ((ROTR(x, 7)) ^ (ROTR(x, 18)) ^ (x >> 3))
#define o1(x) ((ROTR(x, 17)) ^ (ROTR(x, 19)) ^ (x >> 10))

#define BYTE_ARRAY_TO_UINT32_T(x) ((x[0] << 24) + (x[1] << 16) + (x[2] << 8) + x[3])
#define UINT32_T_TO_BYTE_ARRAY(x, arr)       \
{                                            \
	*(arr + 3) = (unsigned char)(x      );   \
	*(arr + 2) = (unsigned char)(x >> 8 );   \
	*(arr + 1) = (unsigned char)(x >> 16);   \
	*(arr + 0) = (unsigned char)(x >> 24);   \
}

//32 bits per word
class MessageWord
{
public:
	MessageWord(const byte* bytes)
	{
		memcpy(data, bytes, 4);
	}

	MessageWord(uint32_t bytes)
	{
		byte tmp[4];
		memcpy(tmp, &bytes, 4);
		for (unsigned int i = 0; i < 4; i++)
			data[3 - i] = tmp[i];
	}

	MessageWord()
	{
		memset(data, 0, 4);
	}

	byte data[4];

	uint32_t getData() const
	{
		return BYTE_ARRAY_TO_UINT32_T(data);
	}
};

//512 bits per block
class MessageBlock
{
public:
	MessageBlock(unsigned char* bytes)
	{
		//assumes 64 byte block
		//64 / 4 = 16 words per block
		for (uint32_t i = 0; i < 16; i++)
			data[i] = MessageWord(bytes + i * 4);
	}

	//32 bits per word (4 unsigned chars)
	const MessageWord& getWord(unsigned int j) const
	{
		return data[j];
	}

private:
	MessageWord data[16];
};

//Varying amount of blocks per message
class Message
{
public:
	int init(const std::vector<unsigned char>& bytes);

	unsigned int getMessageBlockCount() const;
	
	const MessageBlock& getMessageBlock(unsigned int i) const;

private:
	std::vector<MessageBlock> blocks;
};

//2048 bits per schedule
class MessageSchedule
{
public:
	MessageSchedule(Message m, uint32_t i);

	const MessageWord& getWord(unsigned int j) const
	{
		return data[j];
	}

private:
	MessageWord data[64];
};

//Returns the sha256 hash of a string, input
extern std::string sha256(std::string input);