#include "crypto_guard_ctx.h"

#include <print>
#include <openssl/evp.h>

namespace CryptoGuard {

struct CryptoGuardCtx::Impl
{
  std::string CalculateChecksum(std::iostream &inStream)
  {
    std::string res;

    char mess1[] = "Test Message\n";
    char mess2[] = "Hello World\n";

    unsigned char digest[EVP_MAX_MD_SIZE];

    const EVP_MD* md = EVP_get_digestbyname("SHA-256");
    if (md == nullptr)
    {
      return res;
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx = nullptr)
    {
      return res;
    }

    unsigned int digestLen = 0;

    EVP_DigestInit_ex2(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, mess1, strlen(mess1));
    EVP_DigestUpdate(mdctx, mess2, strlen(mess2));
    EVP_DigestFinal_ex(mdctx, digest, &digestLen);
    EVP_MD_CTX_free(mdctx);

    for (size_t i = 0; i < digestLen; i++)
    {
      std::print("{:02x}", digest[i]);
    }

    std::println("");

    return res;
  }
};

// =============================================================================

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>())
{
}

// =============================================================================

CryptoGuardCtx::~CryptoGuardCtx()
{
}

// =============================================================================

std::string CryptoGuardCtx::CalculateChecksum(std::iostream& inStream)
{
  return pImpl_->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard
