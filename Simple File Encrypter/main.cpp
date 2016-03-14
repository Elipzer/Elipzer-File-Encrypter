#include <iostream>
#include <sstream>
#include <vector>
#include <fstream>
#include <windows.h>
#include "util.h"
#include "sha256.h"

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

std::vector<unsigned int> getMoveKey(const std::string& hash, std::vector<unsigned int>& movekey, unsigned int slotDepth)
{
	std::vector<unsigned int> slots;
	slots.reserve(8 * slotDepth);

	for (unsigned int i = 0; i < 8 * slotDepth; i++)
		slots.push_back(i);

	std::vector<unsigned char> digest = getHexChars(hash);
	movekey.clear();
	movekey.reserve(8 * slotDepth);

	for (unsigned int o = 0; o < 8 * slotDepth; o++)
	{
		unsigned int dgst = digest[o];
		unsigned int dgstm = dgst % slots.size();
		unsigned int slts = slots[dgstm];
		slots.erase(slots.begin() + dgstm);
		movekey.push_back(slts);
	}

	return movekey;
}

void encrypt(std::vector<unsigned char> data, std::string password, std::vector<unsigned char>& outBytes)
{
	std::string hash = sha256(password);
	outBytes.reserve(data.size());

	//Normal Part
	for (unsigned int i = 0; i < (unsigned int)(data.size() / 4); i++)
	{
		unsigned char* bytes_i = &(data[0]) + i * 4;

		//each bit in the bytes has its own number as described above.

		//Possibly faster if not using bools but just store the char values and not have to do 32 != operations

		std::vector<bool> bits = {
			(bytes_i[0] & 0x80) != 0, (bytes_i[0] & 0x40) != 0, (bytes_i[0] & 0x20) != 0, (bytes_i[0] & 0x10) != 0, (bytes_i[0] & 0x08) != 0, (bytes_i[0] & 0x04) != 0, (bytes_i[0] & 0x02) != 0, (bytes_i[0] & 0x01) != 0,
			(bytes_i[1] & 0x80) != 0, (bytes_i[1] & 0x40) != 0, (bytes_i[1] & 0x20) != 0, (bytes_i[1] & 0x10) != 0, (bytes_i[1] & 0x08) != 0, (bytes_i[1] & 0x04) != 0, (bytes_i[1] & 0x02) != 0, (bytes_i[1] & 0x01) != 0,
			(bytes_i[2] & 0x80) != 0, (bytes_i[2] & 0x40) != 0, (bytes_i[2] & 0x20) != 0, (bytes_i[2] & 0x10) != 0, (bytes_i[2] & 0x08) != 0, (bytes_i[2] & 0x04) != 0, (bytes_i[2] & 0x02) != 0, (bytes_i[2] & 0x01) != 0,
			(bytes_i[3] & 0x80) != 0, (bytes_i[3] & 0x40) != 0, (bytes_i[3] & 0x20) != 0, (bytes_i[3] & 0x10) != 0, (bytes_i[3] & 0x08) != 0, (bytes_i[3] & 0x04) != 0, (bytes_i[3] & 0x02) != 0, (bytes_i[3] & 0x01) != 0,
		};

		std::vector<unsigned int> slots = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		};

		hash = sha256(hash);

		std::vector<unsigned int> movekey;
		getMoveKey(hash, movekey, 4);

		std::vector<unsigned char> newBytes;
		newBytes.resize(4, 0x00);

		for (unsigned int o = 0; o < 4; o++)
		{
			for (unsigned int u = 0; u < 8; u++)
			{
				newBytes[o] += ((bits[movekey[o * 8 + u]] ? 1 : 0) * (0x80 >> u));
			}
		}

		for (unsigned int o = 0; o < newBytes.size(); o++)
			outBytes.push_back(newBytes[o]);
	}

	//Extra stuff at the end of the file if it is not a perfect length
	switch (data.size() % 4)
	{
	case 0:
		break;
	case 1:
	{
		unsigned char* bytes_i = &(data[0]) + data.size() - 1;

		//each bit in the bytes has its own number as described above.

		//Possibly faster if not using bools but just store the char values and not have to do 32 != operations

		std::vector<bool> bits = {
			(bytes_i[0] & 0x80) != 0, (bytes_i[0] & 0x40) != 0, (bytes_i[0] & 0x20) != 0, (bytes_i[0] & 0x10) != 0, (bytes_i[0] & 0x08) != 0, (bytes_i[0] & 0x04) != 0, (bytes_i[0] & 0x02) != 0, (bytes_i[0] & 0x01) != 0,
		};

		hash = sha256(hash);

		std::vector<unsigned int> movekey;
		getMoveKey(hash, movekey, 1);

		std::vector<unsigned char> newBytes;
		newBytes.resize(1, 0x00);

		for (unsigned int o = 0; o < 1; o++)
		{
			for (unsigned int u = 0; u < 8; u++)
			{
				newBytes[o] += ((bits[movekey[o * 8 + u]] ? 1 : 0) * (0x80 >> u));
			}
		}

		for (unsigned int o = 0; o < newBytes.size(); o++)
			outBytes.push_back(newBytes[o]);
		break;
	}
	case 2:
	{
		unsigned char* bytes_i = &(data[0]) + data.size() - 2;

		//each bit in the bytes has its own number as described above.

		//Possibly faster if not using bools but just store the char values and not have to do 32 != operations

		std::vector<bool> bits = {
			(bytes_i[0] & 0x80) != 0, (bytes_i[0] & 0x40) != 0, (bytes_i[0] & 0x20) != 0, (bytes_i[0] & 0x10) != 0, (bytes_i[0] & 0x08) != 0, (bytes_i[0] & 0x04) != 0, (bytes_i[0] & 0x02) != 0, (bytes_i[0] & 0x01) != 0,
			(bytes_i[1] & 0x80) != 0, (bytes_i[1] & 0x40) != 0, (bytes_i[1] & 0x20) != 0, (bytes_i[1] & 0x10) != 0, (bytes_i[1] & 0x08) != 0, (bytes_i[1] & 0x04) != 0, (bytes_i[1] & 0x02) != 0, (bytes_i[1] & 0x01) != 0,
		};

		hash = sha256(hash);

		std::vector<unsigned int> movekey;
		getMoveKey(hash, movekey, 2);

		std::vector<unsigned char> newBytes;
		newBytes.resize(2, 0x00);

		for (unsigned int o = 0; o < 2; o++)
		{
			for (unsigned int u = 0; u < 8; u++)
			{
				newBytes[o] += ((bits[movekey[o * 8 + u]] ? 1 : 0) * (0x80 >> u));
			}
		}

		for (unsigned int o = 0; o < newBytes.size(); o++)
			outBytes.push_back(newBytes[o]);
		break;
	}
	case 3:
	{
		unsigned char* bytes_i = &(data[0]) + data.size() - 3;

		//each bit in the bytes has its own number as described above.

		//Possibly faster if not using bools but just store the char values and not have to do 32 != operations

		std::vector<bool> bits = {
			(bytes_i[0] & 0x80) != 0, (bytes_i[0] & 0x40) != 0, (bytes_i[0] & 0x20) != 0, (bytes_i[0] & 0x10) != 0, (bytes_i[0] & 0x08) != 0, (bytes_i[0] & 0x04) != 0, (bytes_i[0] & 0x02) != 0, (bytes_i[0] & 0x01) != 0,
			(bytes_i[1] & 0x80) != 0, (bytes_i[1] & 0x40) != 0, (bytes_i[1] & 0x20) != 0, (bytes_i[1] & 0x10) != 0, (bytes_i[1] & 0x08) != 0, (bytes_i[1] & 0x04) != 0, (bytes_i[1] & 0x02) != 0, (bytes_i[1] & 0x01) != 0,
			(bytes_i[2] & 0x80) != 0, (bytes_i[2] & 0x40) != 0, (bytes_i[2] & 0x20) != 0, (bytes_i[2] & 0x10) != 0, (bytes_i[2] & 0x08) != 0, (bytes_i[2] & 0x04) != 0, (bytes_i[2] & 0x02) != 0, (bytes_i[2] & 0x01) != 0,
		};

		hash = sha256(hash);

		std::vector<unsigned int> movekey;
		getMoveKey(hash, movekey, 3);

		std::vector<unsigned char> newBytes;
		newBytes.resize(3, 0x00);

		for (unsigned int o = 0; o < 3; o++)
		{
			for (unsigned int u = 0; u < 8; u++)
			{
				newBytes[o] += ((bits[movekey[o * 8 + u]] ? 1 : 0) * (0x80 >> u));
			}
		}

		for (unsigned int o = 0; o < newBytes.size(); o++)
			outBytes.push_back(newBytes[o]);
		break;
	}
	default:
		exit(-4);
		break;
	}
}

void decrypt(std::vector<unsigned char> data, std::string password, std::vector<unsigned char>& outBytes)
{
	std::string hash = sha256(password);
	outBytes.reserve(data.size());

	//Normal Part
	for (unsigned int i = 0; i < (unsigned int)(data.size() / 4); i++)
	{
		unsigned char* bytes_i = &(data[0]) + i * 4;

		hash = sha256(hash);

		std::vector<unsigned int> movekey;
		getMoveKey(hash, movekey, 4);

		std::vector<unsigned char> newBytes;
		newBytes.resize(4, 0x00);

		for (unsigned int o = 0; o < movekey.size(); o++)
		{
			//Find slot and put it there.
			unsigned int mvko = movekey[o];
			newBytes[mvko / 8] += ((bytes_i[o / 8] & (0x80 >> o % 8)) ? 1 : 0) * (0x80 >> (mvko % 8));
		}

		for (unsigned int o = 0; o < newBytes.size(); o++)
			outBytes.push_back(newBytes[o]);
	}

	//Extra stuff at the end of the file if it is not a perfect length
	switch (data.size() % 4)
	{
	case 0:
		break;
	case 1:
	{
		unsigned char* bytes_i = &(data[0]) + data.size() - 1;

		//each bit in the bytes has its own number as described above.

		//Possibly faster if not using bools but just store the char values and not have to do 32 != operations

		hash = sha256(hash);

		std::vector<unsigned int> movekey;
		getMoveKey(hash, movekey, 1);

		std::vector<unsigned char> newBytes;
		newBytes.resize(1, 0x00);

		for (unsigned int o = 0; o < movekey.size(); o++)
		{
			//Find slot and put it there.
			unsigned int mvko = movekey[o];
			newBytes[mvko / 8] += ((bytes_i[o / 8] & (0x80 >> o % 8)) ? 1 : 0) * (0x80 >> (mvko % 8));
		}

		for (unsigned int o = 0; o < newBytes.size(); o++)
			outBytes.push_back(newBytes[o]);
		break;
	}
	case 2:
	{
		unsigned char* bytes_i = &(data[0]) + data.size() - 2;

		hash = sha256(hash);

		std::vector<unsigned int> movekey;
		getMoveKey(hash, movekey, 2);

		std::vector<unsigned char> newBytes;
		newBytes.resize(2, 0x00);

		for (unsigned int o = 0; o < movekey.size(); o++)
		{
			//Find slot and put it there.
			unsigned int mvko = movekey[o];
			newBytes[mvko / 8] += ((bytes_i[o / 8] & (0x80 >> o % 8)) ? 1 : 0) * (0x80 >> (mvko % 8));
		}

		for (unsigned int o = 0; o < newBytes.size(); o++)
			outBytes.push_back(newBytes[o]);
		break;
	}
	case 3:
	{
		unsigned char* bytes_i = &(data[0]) + data.size() - 3;

		hash = sha256(hash);

		std::vector<unsigned int> movekey;
		getMoveKey(hash, movekey, 3);

		std::vector<unsigned char> newBytes;
		newBytes.resize(3, 0x00);

		for (unsigned int o = 0; o < movekey.size(); o++)
		{
			//Find slot and put it there.
			unsigned int mvko = movekey[o];
			newBytes[mvko / 8] += ((bytes_i[o / 8] & (0x80 >> o % 8)) ? 1 : 0) * (0x80 >> (mvko % 8));
		}

		for (unsigned int o = 0; o < newBytes.size(); o++)
			outBytes.push_back(newBytes[o]);
		break;
	}
	default:
		exit(-4);
		break;
	}
}

bool endswith(const std::string& fullString, const std::string& ending)
{
	if (fullString.length() >= ending.length())
		return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
	else
		return false;
}

int main(int argc, char *argv[])
{
	SetConsoleTitle("Elipzer Encrypter / Decrypter v1.0.0");

	if (argc < 2)
	{
		std::cout << "No File Specified." << std::endl;
		system("PAUSE");
		return -6;
	}

	std::string fileName = std::string(argv[1]);//"C:/Users/Elipzer/Development/VS 2015/Simple File Encrypter/Debug/toencrypt.txt.epzcrypto";
	std::string extension = ".epzcrypto";

	std::cout << "File:" << std::endl << fileName << std::endl << std::endl;

	if (endswith(fileName, extension))
	{
		//Decrypt

		std::cout << "Decrypting File Using Elipzer Encrypter/Decrypter v1.0.0" << std::endl << std::endl;

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

		std::cout << "Encrypting File Using Elipzer Encrypter/Decrypter v1.0.0" << std::endl << std::endl;

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