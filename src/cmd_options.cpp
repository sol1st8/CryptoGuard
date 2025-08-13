#include "cmd_options.h"

#include <iostream>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    namespace po = boost::program_options;

    desc_.add_options()
        ("help,h", "Show help")
        ("command,c", po::value<std::string>(), "Command (encrypt/decrypt/checksum)")
        ("input,i", po::value<std::string>(&inputFile_), "Input file")
        ("output,o", po::value<std::string>(&outputFile_), "Output file")
        ("password,p", po::value<std::string>(&password_), "Password");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    if (vm.contains("help")) {
        desc_.print(std::cout);
        return;
    }

    if (!vm.contains("command")) {
        throw std::runtime_error("Missing command value");
    }

    std::string_view command = vm["command"].as<std::string>();
    auto it = commandMapping_.find(command);
    if (it == commandMapping_.end()) {
        throw std::invalid_argument("Unsupported command");
    }
    command_ = it->second;
}

}  // namespace CryptoGuard