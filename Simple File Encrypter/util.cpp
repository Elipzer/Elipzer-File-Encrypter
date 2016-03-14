#include "util.h"

#include <iostream>

//Adapted from UnraveledEngine by Elipzer
bool loadFileToBuffer(std::string filePath, std::vector<unsigned char>& outBytes)
{
	std::ifstream fileStream(filePath, std::ios::binary);

	if (fileStream.fail())
	{
		perror(filePath.c_str());
		return false;
	}

	fileStream.seekg(0, std::ios::end);
	unsigned int size = (unsigned int)fileStream.tellg();
	fileStream.seekg(0, std::ios::beg);
	size -= (unsigned int)fileStream.tellg();

	if (size == 0)
	{
		std::cout << "Nothing inside of the file" << std::endl;
		return false;
	}

	outBytes.resize(size);

	fileStream.read((char *)&(outBytes[0]), size);
	fileStream.close();
	return true;
}

bool saveFileFromBuffer(std::string filePath, const std::vector<unsigned char>& inBytes)
{
	std::ofstream fileStream(filePath, std::ios::binary);

	if (fileStream.fail())
	{
		perror(filePath.c_str());
		return false;
	}

	fileStream.write((char *)&(inBytes[0]), inBytes.size());
	fileStream.flush();
	fileStream.close();
	return true;
}