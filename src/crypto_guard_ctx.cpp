#include "crypto_guard_ctx.h"

#include <print>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/err.h>

namespace CryptoGuard {

struct CryptoGuardCtx::Impl
{
  std::string CalculateChecksum(std::iostream& inStream)
  {
    std::string res;

    inStream.seekg(0, std::ios::end);
    auto fsize = inStream.tellg();
    inStream.seekg(0, std::ios::beg);

    std::string buf(fsize, '\0');

    inStream.read(&buf[0], fsize);

    unsigned char digest[EVP_MAX_MD_SIZE];

    const EVP_MD* md = EVP_get_digestbyname("sha256");
    if (md == nullptr)
    {
      throw std::runtime_error("EVP_get_digestbyname()");
    }

    using EvpCtxPtr = std::unique_ptr<
      EVP_MD_CTX,
      decltype( [](EVP_MD_CTX* ptr){ EVP_MD_CTX_free(ptr); } )
    >;

    EvpCtxPtr mdctx;
    mdctx.reset(EVP_MD_CTX_new());

    if (mdctx == nullptr)
    {
      throw std::runtime_error("EVP_MD_CTX_new()");
    }

    unsigned int digestLen = 0;

    if (not EVP_DigestInit_ex2(mdctx.get(), md, nullptr))
    {
      throw std::runtime_error("EVP_DigestInit_ex2()");
    }

    if (not EVP_DigestUpdate(mdctx.get(), buf.data(), buf.length()))
    {
      throw std::runtime_error("EVP_DigestUpdate()");
    }

    if (not EVP_DigestFinal_ex(mdctx.get(), digest, &digestLen))
    {
      throw std::runtime_error("EVP_DigestFinal_ex()");
    }

    std::stringstream ss;

    ss << std::hex << std::setfill('0');

    for (size_t i = 0; i < digestLen; i++)
    {
      ss << std::setw(2) << +digest[i];
    }

    res = ss.str();

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
