#include "crypto_guard_ctx.h"

#include <array>
#include <iostream>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <vector>

using namespace std::literals;

namespace CryptoGuard {

const size_t BUFF_SIZE = 1024;

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl {
public:
    Impl() { OpenSSL_add_all_algorithms(); }

    ~Impl() { EVP_cleanup(); }

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }

    void EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
        if (!inStream.good() && !outStream.good()) {
            throw std::runtime_error("Stream error");
        }

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;
        std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })> ctx{
            EVP_CIPHER_CTX_new()};

        if (!EVP_CIPHER_CTX_init(ctx.get())) {
            throw std::runtime_error("Failed to create cipher context for encryption");
        }

        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                               params.encrypt)) {
            throw std::runtime_error("Failed to initialize cipher context for encryption");
        }

        std::vector<unsigned char> outBuf(BUFF_SIZE + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(BUFF_SIZE);
        int outLen = 0;

        while (inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size())) {
            if (!inStream.good()) {
                throw std::runtime_error("Input stream error during encryption read operation");
            }
            if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inStream.gcount())) {
                throw std::runtime_error("Failed to update cipher during encryption");
            }
            outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
            if (!outStream.good()) {
                throw std::runtime_error("Output stream error during encryption write operation");
            }
        }
        if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inStream.gcount())) {
            throw std::runtime_error("Failed to process remaining data during encryption");
        }

        outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
        if (!outStream.good()) {
            throw std::runtime_error("Output stream error during final encryption write");
        }

        if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
            throw std::runtime_error("Failed to finalize encryption process");
        }
        outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
        if (!outStream.good()) {
            throw std::runtime_error{"Output stream error after finalizing encryption"};
        }
    }

    void DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
        if (!inStream.good() && !outStream.good()) {
            throw std::runtime_error("Stream error");
        }

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 0;
        std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })> ctx{
            EVP_CIPHER_CTX_new()};

        if (!EVP_CIPHER_CTX_init(ctx.get())) {
            throw std::runtime_error("Failed to initialize cipher context for decryption");
        }

        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                               params.encrypt)) {
            throw std::runtime_error("Failed to initialize cipher operation for decryption");
        }

        std::vector<unsigned char> outBuf(BUFF_SIZE + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(BUFF_SIZE);
        int outLen = 0;

        while (inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size())) {
            if (!inStream.good()) {
                throw std::runtime_error("Input stream error during decryption read operation");
            }
            if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inStream.gcount())) {
                throw std::runtime_error("Failed to update cipher during decryption");
            }
            outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
            if (!outStream.good()) {
                throw std::runtime_error("Output stream error during decryption write operation");
            }
        }
        if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inStream.gcount())) {
            throw std::runtime_error("Failed to process remaining data during decryption");
        }

        outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
        if (!outStream.good()) {
            throw std::runtime_error("Output stream error during final decryption write");
        }

        if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
            throw std::runtime_error(
                "Failed to finalize decryption process (possibly corrupted data or wrong password)");
        }
        outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
        if (!outStream.good()) {
            throw std::runtime_error{"Output stream error after finalizing decryption"};
        }
    }

    std::string CalculateChecksum(std::iostream &inStream) {
        std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })> ctx{EVP_MD_CTX_new()};

        auto digestUpdate = [&](std::vector<unsigned char> &inBuf) {
            if (!EVP_DigestUpdate(ctx.get(), inBuf.data(), inStream.gcount())) {
                throw std::runtime_error("Failed to update digest calculation");
            }
        };

        if (!inStream.good()) {
            throw std::runtime_error("Input stream error before checksum calculation");
        }

        if (!EVP_MD_CTX_init(ctx.get())) {
            throw std::runtime_error("Failed to initialize digest context");
        }

        std::array<unsigned char, EVP_MAX_MD_SIZE> md_value;
        unsigned int md_len;
        const EVP_MD *md = EVP_get_digestbyname("SHA256");

        if (!EVP_DigestInit(ctx.get(), md)) {
            throw std::runtime_error("Failed to initialize digest with SHA256 algorithm");
        }

        std::vector<unsigned char> inBuf(BUFF_SIZE);

        while (inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size())) {
            if (!inStream.good()) {
                throw std::runtime_error("Input stream error during checksum calculation");
            }
            digestUpdate(inBuf);
        }
        digestUpdate(inBuf);

        if (!EVP_DigestFinal(ctx.get(), md_value.data(), &md_len)) {
            throw std::runtime_error("Failed to finalize digest calculation");
        }

        std::stringstream ss;
        for (unsigned int i = 0; i < md_len; i++) {
            std::print(ss, "{:02x}", md_value[i]);
        }

        return ss.str();
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
