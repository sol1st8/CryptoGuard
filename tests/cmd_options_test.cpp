#include <gtest/gtest.h>

#include "cmd_options.h"

TEST(ProgramOptions, HelpOption) {
    CryptoGuard::ProgramOptions prog_opt;
    char argv0[] = "CryptoGuard";
    char argv1[] = "--help";
    char *argv[] = {argv0, argv1};
    int argc = 2;
    EXPECT_NO_THROW(prog_opt.Parse(argc, argv));
}

TEST(ProgramOptions, MissingParams) {
    CryptoGuard::ProgramOptions prog_opt;
    char argv0[] = "CryptoGuard";
    char *argv[] = {argv0};
    int argc = 1;
    EXPECT_THROW(prog_opt.Parse(argc, argv), std::runtime_error);
}

TEST(ProgramOptions, ValidCommandLine) {
    CryptoGuard::ProgramOptions prog_opt;
    char argv0[] = "CryptoGuard";
    char argv1[] = "--command";
    char argv2[] = "encrypt";
    char argv3[] = "--input";
    char argv4[] = "in.txt";
    char argv5[] = "--output";
    char argv6[] = "out.txt";
    char argv7[] = "--password";
    char argv8[] = "123";
    char *argv[] = {argv0, argv1, argv2, argv3, argv4, argv5, argv6, argv7, argv8};
    int argc = 9;

    EXPECT_NO_THROW(prog_opt.Parse(argc, argv));
    EXPECT_EQ(prog_opt.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(prog_opt.GetInputFile(), "in.txt");
    EXPECT_EQ(prog_opt.GetOutputFile(), "out.txt");
    EXPECT_EQ(prog_opt.GetPassword(), "123");
}

TEST(ProgramOptions, ShortOptions) {
    CryptoGuard::ProgramOptions prog_opt;
    char argv0[] = "CryptoGuard";
    char argv1[] = "-c";
    char argv2[] = "encrypt";
    char argv3[] = "-i";
    char argv4[] = "in.txt";
    char argv5[] = "-o";
    char argv6[] = "out.txt";
    char argv7[] = "-p";
    char argv8[] = "123";
    char *argv[] = {argv0, argv1, argv2, argv3, argv4, argv5, argv6, argv7, argv8};
    int argc = 9;

    EXPECT_NO_THROW(prog_opt.Parse(argc, argv));
    EXPECT_EQ(prog_opt.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(prog_opt.GetInputFile(), "in.txt");
    EXPECT_EQ(prog_opt.GetOutputFile(), "out.txt");
    EXPECT_EQ(prog_opt.GetPassword(), "123");
}

TEST(ProgramOptions, MissingCommand) {
    CryptoGuard::ProgramOptions prog_opt;
    char argv0[] = "CryptoGuard";
    char argv1[] = "--input";
    char argv2[] = "in.txt";
    char argv3[] = "--output";
    char argv4[] = "out.txt";
    char argv5[] = "--password";
    char argv6[] = "123";
    char *argv[] = {argv0, argv1, argv2, argv3, argv4, argv5, argv6};
    int argc = 7;
    EXPECT_THROW(prog_opt.Parse(argc, argv), std::runtime_error);
}

TEST(ProgramOptions, InvalidCommand) {
    CryptoGuard::ProgramOptions prog_opt;
    char argv0[] = "CryptoGuard";
    char argv1[] = "--command";
    char argv2[] = "invalid";
    char argv3[] = "--input";
    char argv4[] = "in.txt";
    char argv5[] = "--output";
    char argv6[] = "out.txt";
    char argv7[] = "--password";
    char argv8[] = "123";
    char *argv[] = {argv0, argv1, argv2, argv3, argv4, argv5, argv6, argv7, argv8};
    int argc = 9;
    EXPECT_THROW(prog_opt.Parse(argc, argv), std::invalid_argument);
}

TEST(ProgramOptions, DifferentCommands) {
    // Test encrypt
    {
        CryptoGuard::ProgramOptions prog_opt;
        char argv0[] = "CryptoGuard";
        char argv1[] = "--command";
        char argv2[] = "encrypt";
        char *argv[] = {argv0, argv1, argv2};
        int argc = 3;
        EXPECT_NO_THROW(prog_opt.Parse(argc, argv));
        EXPECT_EQ(prog_opt.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    }

    // Test decrypt
    {
        CryptoGuard::ProgramOptions prog_opt;
        char argv0[] = "CryptoGuard";
        char argv1[] = "--command";
        char argv2[] = "decrypt";
        char *argv[] = {argv0, argv1, argv2};
        int argc = 3;
        EXPECT_NO_THROW(prog_opt.Parse(argc, argv));
        EXPECT_EQ(prog_opt.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    }

    // Test checksum
    {
        CryptoGuard::ProgramOptions prog_opt;
        char argv0[] = "CryptoGuard";
        char argv1[] = "--command";
        char argv2[] = "checksum";
        char *argv[] = {argv0, argv1, argv2};
        int argc = 3;
        EXPECT_NO_THROW(prog_opt.Parse(argc, argv));
        EXPECT_EQ(prog_opt.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
    }
}