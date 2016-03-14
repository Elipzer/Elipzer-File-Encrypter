#pragma once

#include <fstream>
#include <vector>

extern bool loadFileToBuffer(std::string filePath, std::vector<unsigned char>& outBytes);

extern bool saveFileFromBuffer(std::string filePath, const std::vector<unsigned char>& inBytes);