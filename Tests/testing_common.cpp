#include "testing_common.h"

Buffer read_file(const std::wstring& file_path)
{
	std::ifstream file(file_path, std::ifstream::ate | std::ifstream::binary);

	Buffer buffer(static_cast<uint32_t>(file.tellg()));
	file.seekg(std::ios::beg);
	file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
	return buffer;
}
