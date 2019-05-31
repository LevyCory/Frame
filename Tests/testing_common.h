#include <string>
#include <vector>
#include <fstream>

using Buffer = std::vector<uint8_t>;

Buffer read_file(const std::wstring& file_path);

