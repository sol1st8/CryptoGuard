#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>

std::fstream GetFileStream(std::string path) {
    std::fstream stream{path};
    if (!stream.is_open()) {
        throw std::runtime_error("Failed to open file: " + path);
    }
    return stream;
}

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

        if (!options.GetCommand().has_value()) {
            throw std::runtime_error("No command specified. Available commands: encrypt, decrypt, checksum");
        }

        switch (*options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            if (options.GetInputFile() == options.GetOutputFile()) {
                throw std::runtime_error("Input and output files must be different for encryption");
            }

            std::fstream in = GetFileStream(options.GetInputFile());
            std::fstream out = GetFileStream(options.GetOutputFile());

            cryptoCtx.EncryptFile(in, out, options.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }

        case COMMAND_TYPE::DECRYPT: {
            if (options.GetInputFile() == options.GetOutputFile()) {
                throw std::runtime_error("Input and output files must be different for decryption");
            }

            std::fstream in = GetFileStream(options.GetInputFile());
            std::fstream out = GetFileStream(options.GetOutputFile());

            cryptoCtx.DecryptFile(in, out, options.GetPassword());
            std::print("File decoded successfully\n");
            break;
        }

        case COMMAND_TYPE::CHECKSUM: {
            std::fstream in = GetFileStream(options.GetInputFile());
            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(in));
            break;
        }

        default:
            throw std::runtime_error{"Unsupported command"};
        }
    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}