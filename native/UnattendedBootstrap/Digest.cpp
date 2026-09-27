#include "Bootstrap.h"
#include <bcrypt.h>
#include <array>

namespace jts {
namespace {
class Sha256 final {
    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::vector<unsigned char> object_;
public:
    Sha256() {
        try {
            Require(BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, L"BOOTSTRAP_HASH_UNAVAILABLE");
            DWORD size = 0, returned = 0;
            Require(BCryptGetProperty(algorithm_, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&size), sizeof(size), &returned, 0) >= 0
                && returned == sizeof(size) && size != 0 && size <= 1024 * 1024, L"BOOTSTRAP_HASH_UNAVAILABLE");
            object_.resize(size);
            Require(BCryptCreateHash(algorithm_, &hash_, object_.data(), size, nullptr, 0, 0) >= 0, L"BOOTSTRAP_HASH_UNAVAILABLE");
        } catch (...) { Close(); throw; }
    }
    ~Sha256() { Close(); }
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;
    void Add(const unsigned char* bytes, ULONG size) {
        Require(BCryptHashData(hash_, const_cast<PUCHAR>(bytes), size, 0) >= 0, L"BOOTSTRAP_HASH_FAILED");
    }
    std::string Finish() {
        std::array<unsigned char, 32> value{};
        Require(BCryptFinishHash(hash_, value.data(), static_cast<ULONG>(value.size()), 0) >= 0, L"BOOTSTRAP_HASH_FAILED");
        constexpr char alphabet[] = "0123456789abcdef";
        std::string result; result.reserve(64);
        for (const auto byte : value) { result += alphabet[byte >> 4]; result += alphabet[byte & 15]; }
        return result;
    }
private:
    void Close() {
        if (hash_) BCryptDestroyHash(hash_);
        hash_ = nullptr;
        if (algorithm_) BCryptCloseAlgorithmProvider(algorithm_, 0);
        algorithm_ = nullptr;
    }
};
}

std::string HashBytes(const unsigned char* bytes, ULONG length) {
    Sha256 hash; hash.Add(bytes, length); return hash.Finish();
}

std::string HashFile(HANDLE file) {
    LARGE_INTEGER start{};
    Require(SetFilePointerEx(file, start, nullptr, FILE_BEGIN) != FALSE, L"BOOTSTRAP_FILE_HASH_FAILED");
    Sha256 hash; std::vector<unsigned char> buffer(1024 * 1024);
    while (true) {
        DWORD read = 0;
        Require(ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr) != FALSE, L"BOOTSTRAP_FILE_HASH_FAILED");
        if (read == 0) return hash.Finish();
        hash.Add(buffer.data(), read);
    }
}
}
