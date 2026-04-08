#include <gtest/gtest.h>

#include "crypto_guard_ctx.h"

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
