#include <print>
#include <gtest/gtest.h>

#include "crypto_guard_ctx.h"

//
// Since these are unit tests and this is a helper function, we won't do
// rigorous error checking and stuff.
//
std::vector<uint8_t> HexStringToBytes(const std::string& hex)
{
  std::vector<uint8_t> res;

  if (hex.length() % 2 != 0)
  {
    std::println("Input hex string is of invalid length {}", hex.length());
    return res;
  }

  res.reserve(hex.length() / 2);

  try
  {
    for (size_t i = 0; i <= hex.length() - 2; i += 2)
    {
      std::string s(hex.begin() + i, hex.begin() + i + 2);
      uint8_t value = std::stoul(s, nullptr, 16);
      res.push_back(value);
    }
  }
  catch(const std::exception& e)
  {
    std::println("{}", e.what());
    res.clear();
  }

  return res;
}

// =============================================================================

TEST(Checksum, NotEmpty)
{
  CryptoGuard::CryptoGuardCtx instance;

  std::stringstream ss;
  ss << "This is a test.\n";

  const std::string expected =
    "11586d2eb43b73e539caa3d158c883336c0e2c904b309c0c5ffe2c9b83d562a1";

  std::string actual = instance.CalculateChecksum(ss);

  EXPECT_STRCASEEQ(expected.data(), actual.data());
}

// =============================================================================

TEST(Checksum, Empty)
{
  CryptoGuard::CryptoGuardCtx instance;

  std::stringstream ss;

  const std::string expected =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  std::string actual = instance.CalculateChecksum(ss);

  EXPECT_STRCASEEQ(expected.data(), actual.data());
}

// =============================================================================

TEST(Encryption, Empty)
{
  CryptoGuard::CryptoGuardCtx instance;

  const std::string plainText;
  const std::string password = "1234";

  auto expected = HexStringToBytes("0a552eaefba8490bf50315836a9b515a");

  std::stringstream in;

  in << plainText;

  std::stringstream out;

  EXPECT_NO_THROW( instance.EncryptFile(in, out, password) );

  std::string actual = out.str();

  ASSERT_EQ(expected.size(), actual.size());

  for (size_t i = 0; i < expected.size(); i++)
  {
    EXPECT_EQ(expected[i], (uint8_t)actual[i]);
  }

  std::stringstream ss;

  //
  // Get this via our own written binary: 'CryptoGuard --command checksum'
  //
  ss << "60dbb1c7de22a8e7e8d548a8007c776e5e679f52e40074c3eae72faf263fa630";

  std::string expectedChecksum = ss.str();
  std::string actualChecksum;

  EXPECT_NO_THROW( actualChecksum = instance.CalculateChecksum(out) );

  EXPECT_STRCASEEQ(expectedChecksum.data(), actualChecksum.data());
}

// =============================================================================

TEST(Encryption, Success)
{
  CryptoGuard::CryptoGuardCtx instance;

  const std::string plainText = "This is a test.\n";
  const std::string password  = "1234";

  auto expected = HexStringToBytes("28a58927b86ae48aa28236a019cc4b1e4723b16b30f841ca9484def96824489b");

  std::stringstream in;

  in << plainText;

  std::stringstream out;

  EXPECT_NO_THROW( instance.EncryptFile(in, out, password) );

  std::string actual = out.str();

  ASSERT_EQ(expected.size(), actual.size());

  for (size_t i = 0; i < expected.size(); i++)
  {
    EXPECT_EQ(expected[i], (uint8_t)actual[i]);
  }

  std::stringstream ss;

  ss << "cc8b98c923f9b0d3d49539398afe81c4f4ac64a3ee2a39cbf04259d506cc09c6";

  std::string expectedChecksum = ss.str();
  std::string actualChecksum;

  EXPECT_NO_THROW( actualChecksum = instance.CalculateChecksum(out) );

  EXPECT_STRCASEEQ(expectedChecksum.data(), actualChecksum.data());
}

// =============================================================================

TEST(Decryption, Empty)
{
  CryptoGuard::CryptoGuardCtx instance;

  auto bytes = HexStringToBytes("0a552eaefba8490bf50315836a9b515a");

  const std::string cipherText(bytes.begin(), bytes.end());
  const std::string password = "1234";

  const std::string expected;

  std::stringstream in;

  in << cipherText;

  std::stringstream out;

  EXPECT_NO_THROW( instance.DecryptFile(in, out, password) );

  std::string actual = out.str();

  EXPECT_STRCASEEQ(expected.data(), actual.data());

  std::stringstream ss;

  ss << "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  std::string expectedChecksum = ss.str();
  std::string actualChecksum;

  EXPECT_NO_THROW( actualChecksum = instance.CalculateChecksum(out) );

  EXPECT_STRCASEEQ(expectedChecksum.data(), actualChecksum.data());
}

// =============================================================================

TEST(Decryption, Success)
{
  CryptoGuard::CryptoGuardCtx instance;

  auto bytes = HexStringToBytes("28a58927b86ae48aa28236a019cc4b1e4723b16b30f841ca9484def96824489b");

  const std::string cipherText(bytes.begin(), bytes.end());
  const std::string password = "1234";

  const std::string expected = "This is a test.\n";

  std::stringstream in;

  in << cipherText;

  std::stringstream out;

  EXPECT_NO_THROW( instance.DecryptFile(in, out, password) );

  std::string actual = out.str();

  EXPECT_STRCASEEQ(expected.data(), actual.data());

  std::stringstream ss;

  ss << "11586d2eb43b73e539caa3d158c883336c0e2c904b309c0c5ffe2c9b83d562a1";

  std::string expectedChecksum = ss.str();
  std::string actualChecksum;

  EXPECT_NO_THROW( actualChecksum = instance.CalculateChecksum(out) );

  EXPECT_STRCASEEQ(expectedChecksum.data(), actualChecksum.data());
}

// =============================================================================

TEST(Decryption, WrongPassword)
{
  CryptoGuard::CryptoGuardCtx instance;

  auto bytes = HexStringToBytes("28a58927b86ae48aa28236a019cc4b1e4723b16b30f841ca9484def96824489b");

  const std::string cipherText(bytes.begin(), bytes.end());
  const std::string password = "12345";

  const std::string expected = "This is a test.\n";

  std::stringstream in;

  in << cipherText;

  std::stringstream out;

  EXPECT_ANY_THROW( instance.DecryptFile(in, out, password) );
}

// =============================================================================

TEST(Decryption, NotEncrypted)
{
  CryptoGuard::CryptoGuardCtx instance;

  const std::string cipherText = "Not encrypted.";
  const std::string password = "1234";

  const std::string expected = "This is a test.\n";

  std::stringstream in;

  in << cipherText;

  std::stringstream out;

  EXPECT_ANY_THROW( instance.DecryptFile(in, out, password) );
}
