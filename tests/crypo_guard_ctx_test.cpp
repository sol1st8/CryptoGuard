#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>
#include <sstream>
#include <stdexcept>
#include <string>

TEST(CryptoGuardCtx, Encrypt) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in("test");
    std::stringstream out;
    std::ostringstream resStream;
    std::string_view password = "23456";
    ctx.EncryptFile(in, out, password);
    std::array<char, 16> res = {'\xc6', '\x12', '\x9a', '\xb4', '-', ':',    '\xc2', 'P',
                                'N',    '\x8f', ' ',    'p',    'E', '\xe3', '5',    '\x13'};
    resStream.write(res.data(), res.size());
    EXPECT_EQ(resStream.str(), out.str());
}

TEST(CryptoGuardCtx, EncryptAssert) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in("test");
    std::stringstream out(std::ios::in);
    std::string_view password = "23456";
    ASSERT_THROW(ctx.EncryptFile(in, out, password), std::runtime_error);
}

TEST(CryptoGuardCtx, EncryptEmptyPass) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in("test");
    std::stringstream out;
    std::ostringstream resStream;
    std::string_view password = "";
    ctx.EncryptFile(in, out, password);
    std::array<char, 16> res = {'\xab', '\x92', '\xc3', 'Y', '[',  '$', '5',    '[',
                                ';',    '\\',   '\xab', '3', '\f', '}', '\xb2', '\x04'};
    resStream.write(res.data(), res.size());
    EXPECT_EQ(resStream.str(), out.str());
}

TEST(CryptoGuardCtx, Decrypt) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in;
    std::stringstream out;
    std::string_view password = "23456";
    std::array<char, 16> test = {'\xc6', '\x12', '\x9a', '\xb4', '-', ':',    '\xc2', 'P',
                                 'N',    '\x8f', ' ',    'p',    'E', '\xe3', '5',    '\x13'};
    in.write(test.data(), test.size());
    ctx.DecryptFile(in, out, password);

    EXPECT_EQ(out.str(), "test");
}

TEST(CryptoGuardCtx, DecryptEmptyPass) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in;
    std::stringstream out;
    std::string_view password = "";
    std::array<char, 16> test = {'\xab', '\x92', '\xc3', 'Y', '[',  '$', '5',    '[',
                                 ';',    '\\',   '\xab', '3', '\f', '}', '\xb2', '\x04'};
    in.write(test.data(), test.size());
    ctx.DecryptFile(in, out, password);

    EXPECT_EQ(out.str(), "test");
}

TEST(CryptoGuardCtx, DecryptEmptyStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in;
    std::stringstream out;
    std::string_view password = "";
    ASSERT_THROW(ctx.DecryptFile(in, out, password), std::runtime_error);
}

TEST(CryptoGuardCtx, CheckSumVal) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream str("test");
    EXPECT_EQ(ctx.CalculateChecksum(str), "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
}

TEST(CryptoGuardCtx, CheckSumAfterEncrDecr) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::string check = "checkConvert";
    std::stringstream encryptIn(check);
    std::stringstream encryptInCopy(check);
    std::stringstream encryptOut;
    std::stringstream decryptOut;

    ctx.EncryptFile(encryptIn, encryptOut, "12345");
    std::string sum1 = ctx.CalculateChecksum(encryptInCopy);
    ctx.DecryptFile(encryptOut, decryptOut, "12345");
    std::string sum2 = ctx.CalculateChecksum(decryptOut);

    EXPECT_EQ(sum1, sum2);
}

TEST(CryptoGuardCtx, CheckSumEmptyStr) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream str;
    EXPECT_EQ(ctx.CalculateChecksum(str), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}