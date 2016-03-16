#include <iostream>
#include <sstream>
#include <vector>
#include <fstream>
#include <windows.h>
#include "util.h"
#include "sha256.h"

//Steaming Soup Encryption / Decryption


#define BYTE_BITS 8
#define BYTE_FIRST_BIT 0x80

unsigned char getHexChar(std::string value)
{
	std::stringstream ss;
	unsigned int x;
	ss << std::hex << value;
	ss >> x;
	return (unsigned char)x;
}

std::vector<unsigned char> getHexChars(std::string values)
{
	std::vector<unsigned char> ret;
	ret.reserve(values.size() / 2);
	for (unsigned int i = 0; i < values.size() / 2; i++)
		ret.push_back(getHexChar(values.substr(i * 2, 2)));
	return ret;
}

void getMoveKey(const std::string& hash, std::vector<unsigned char>& movekey, unsigned int rows)
{
	std::vector<unsigned char> slots;
	slots.reserve(BYTE_BITS * rows);

	for (unsigned char i = 0; i < BYTE_BITS * rows; i++)
		slots.push_back(i);

	std::vector<unsigned char> digest = getHexChars(hash);
	movekey.clear();
	movekey.reserve(BYTE_BITS * rows);

	for (unsigned int i = 0; i < BYTE_BITS * rows; i++)
	{
		unsigned char dgstm = digest[i] % slots.size();
		unsigned char slts = slots[dgstm];
		slots.erase(slots.begin() + dgstm);
		movekey.push_back(slts);
	}
}

std::vector<unsigned char> generateBits(unsigned char* bytes, unsigned int rows)
{
	std::vector<unsigned char> bits;
	bits.reserve(BYTE_BITS * rows);

	for (unsigned int i = 0; i < BYTE_BITS * rows; i++)
		bits.push_back(bytes[i / BYTE_BITS] & (BYTE_FIRST_BIT >> (i % BYTE_BITS)));
	
	return bits;
}

std::vector<unsigned char> generateEncryptedBytes(std::string& hash, unsigned char* bytes, unsigned int rows)
{
	std::vector<unsigned char> bits = generateBits(bytes, rows);

	hash = sha256(hash);

	std::vector<unsigned char> movekey;
	getMoveKey(hash, movekey, rows);

	std::vector<unsigned char> newBytes;
	newBytes.resize(rows, 0x00);

	for (unsigned int o = 0; o < rows; o++)
		for (unsigned int u = 0; u < BYTE_BITS; u++)
			newBytes[o] += ((bits[movekey[o * BYTE_BITS + u]] ? 1 : 0) * (BYTE_FIRST_BIT >> u));

	return newBytes;
}

void encrypt(std::vector<unsigned char> data, std::string password, std::vector<unsigned char>& outBytes)
{
	const static unsigned int DEFAULT_ROWS = 4;

	std::string hash = sha256(password);
	outBytes.reserve(data.size());

	for (unsigned int i = 0; i < (unsigned int)(data.size() / DEFAULT_ROWS); i++)
	{
		std::vector<unsigned char> encrypted = generateEncryptedBytes(hash, data.data() + i * DEFAULT_ROWS, DEFAULT_ROWS);
		outBytes.insert(outBytes.end(), encrypted.begin(), encrypted.end());
	}

	unsigned int extraEnd = data.size() % DEFAULT_ROWS;
	if (extraEnd > 0)
	{
		std::vector<unsigned char> encrypted = generateEncryptedBytes(hash, data.data() + data.size() - extraEnd, extraEnd);
		outBytes.insert(outBytes.end(), encrypted.begin(), encrypted.end());
	}
}

std::vector<unsigned char> generateDecryptedBytes(std::string& hash, unsigned char* bytes, unsigned int rows)
{
	hash = sha256(hash);

	std::vector<unsigned char> movekey;
	getMoveKey(hash, movekey, rows);

	std::vector<unsigned char> newBytes;
	newBytes.resize(rows, 0x00);

	for (unsigned int o = 0; o < movekey.size(); o++)
	{
		unsigned int mvko = movekey[o];
		newBytes[mvko / BYTE_BITS] += ((bytes[o / BYTE_BITS] & (BYTE_FIRST_BIT >> o % BYTE_BITS)) ? 1 : 0) * (BYTE_FIRST_BIT >> (mvko % BYTE_BITS));
	}

	return newBytes;
}

void decrypt(std::vector<unsigned char> data, std::string password, std::vector<unsigned char>& outBytes)
{
	const static unsigned int DEFAULT_ROWS = 4;

	std::string hash = sha256(password);
	outBytes.reserve(data.size());

	for (unsigned int i = 0; i < (unsigned int)(data.size() / DEFAULT_ROWS); i++)
	{
		std::vector<unsigned char> decrypted = generateDecryptedBytes(hash, data.data() + i * DEFAULT_ROWS, DEFAULT_ROWS);
		outBytes.insert(outBytes.end(), decrypted.begin(), decrypted.end());
	}

	unsigned int extraEnd = data.size() % DEFAULT_ROWS;
	if (extraEnd > 0)
	{
		std::vector<unsigned char> decrypted = generateDecryptedBytes(hash, data.data() + data.size() - extraEnd, extraEnd);
		outBytes.insert(outBytes.end(), decrypted.begin(), decrypted.end());
	}
}

bool endswith(const std::string& fullString, const std::string& ending)
{
	if (fullString.length() >= ending.length())
		return fullString.compare(fullString.length() - ending.length(), ending.length(), ending) == 0;
	else
		return false;
}

int main(int argc, char *argv[])
{
	std::string name = "Elipzer Encrypter / Decrypter v 1.0.0";

	SetConsoleTitle(name.c_str());

	if (argc < 2)
	{
		std::cout << "No File Specified." << std::endl;
		system("PAUSE");
		return -6;
	}

	std::string fileName = std::string(argv[1]);
	std::string extension = ".epzcrypto";

	std::cout << "File:" << std::endl << fileName << std::endl << std::endl;

	if (endswith(fileName, extension))
	{
		//Decrypt

		std::cout << "Decrypting File Using " << name << std::endl << std::endl;

		std::string outFileName = fileName.substr(0, fileName.length() - extension.length());

		std::cout << "Output File:" << std::endl << outFileName << std::endl << std::endl;

		std::cout << "Password: " << std::endl;
		std::string pass;
		std::cin >> pass;

		std::cout << std::endl;

		std::vector<unsigned char> bytes;
		std::vector<unsigned char> outBytes;

		if (!loadFileToBuffer(fileName, bytes))
		{
			std::cout << "Unable to load file" << std::endl;
			system("PAUSE");
			return -1;
		}

		decrypt(bytes, pass, outBytes);

		if (!saveFileFromBuffer(outFileName, outBytes))
		{
			std::cout << "Unable to save file" << std::endl;
			system("PAUSE");
			return -5;
		}

		std::cout << "Decryption Complete. Saved to " << outFileName << std::endl;

	}
	else
	{
		//Encrypt

		std::cout << "Encrypting File Using " << name << std::endl << std::endl;

		std::string outFileName = fileName + extension;

		std::cout << "Output File:" << std::endl << outFileName << std::endl << std::endl;

		std::cout << "Password: " << std::endl;
		std::string pass;
		std::cin >> pass;

		std::cout << std::endl;

		std::vector<unsigned char> bytes;
		std::vector<unsigned char> outBytes;

		if (!loadFileToBuffer(fileName, bytes))
		{
			std::cout << "Unable to load file" << std::endl;
			system("PAUSE");
			return -1;
		}

		encrypt(bytes, pass, outBytes);

		if (!saveFileFromBuffer(outFileName, outBytes))
		{
			std::cout << std::endl << "Unable to save file" << std::endl;
			system("PAUSE");
			return -5;
		}

		std::cout << "Encryption Complete" << std::endl << std::endl << "Saved to:" << std::endl << std::endl << outFileName << std::endl << std::endl;
	}

	system("PAUSE");

	return 0;
}