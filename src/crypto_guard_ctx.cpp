#include "crypto_guard_ctx.h"

#include <print>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/err.h>

#ifdef DEBUG_LOGS
  #define DebugLog(format, ...)          \
    do {                                 \
    printf(format "\n", ##__VA_ARGS__);  \
    fflush(stdout);                      \
    } while (false)
#else
  #define DebugLog(format, ...)
#endif

namespace CryptoGuard {

// =============================================================================

struct CryptoGuardCtx::Impl
{
  struct AesCipherParams
  {
    // AES-256 key size
    static const size_t KEY_SIZE = 32;
    // AES block size (IV length)
    static const size_t IV_SIZE = 16;
    // Cipher algorithm
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();

    // 1 for encryption, 0 for decryption
    int encrypt;
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
  };

  using CipherPtr = std::unique_ptr<
    EVP_CIPHER_CTX,
    decltype(
      [](EVP_CIPHER_CTX* ctx)
      {
        EVP_CIPHER_CTX_free(ctx);
      }
    )
  >;

  CipherPtr cipherIface_;

  // ---------------------------------------------------------------------------

  Impl()
  {
    OpenSSL_add_all_algorithms();
  }

  // ---------------------------------------------------------------------------

  ~Impl()
  {
    EVP_cleanup();
  }

  // ---------------------------------------------------------------------------

  template <typename Vector>
  std::string ToHexString(const Vector& v)
  {
    std::stringstream ss;

    ss << std::hex << std::setfill('0');

    for (auto& c : v)
    {
      ss << std::setw(2) << +c;
    }

    return ss.str();
  }

  // ---------------------------------------------------------------------------

  AesCipherParams CreateChiperParamsFromPassword(std::string_view password)
  {
    AesCipherParams params;

    constexpr std::array<unsigned char, 8> salt =
    { '1', '2', '3', '4', '5', '6', '7', '8' };

    int result = EVP_BytesToKey(
      params.cipher,
      EVP_sha256(),
      salt.data(),
      reinterpret_cast<const unsigned char*>(password.data()),
      password.size(),
      1,
      params.key.data(),
      params.iv.data()
    );

    if (result == 0)
    {
      throw std::runtime_error{"Failed to create a key from password"};
    }

    DebugLog("key = %s", ToHexString(params.key).data());
    DebugLog("iv  = %s", ToHexString(params.iv).data());

    return params;
  }

  // ---------------------------------------------------------------------------

  void LogErrorsSSL()
  {
    // "buf must be at least 256 bytes long"
    char buf[256] {};

    unsigned long ec = 0;
    while (ec = ERR_get_error())
    {
      ERR_error_string(ec, buf);
      std::println("{}", buf);
    }
  }

  // ---------------------------------------------------------------------------

  std::string ReadFile(std::iostream& file)
  {
    file.seekg(0, std::ios::end);
    auto fsize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::string contents(fsize, '\0');

    file.read(&contents[0], fsize);

    return contents;
  }

  // ---------------------------------------------------------------------------

  std::string CalculateChecksum(std::iostream& inStream)
  {
    std::string res;

    std::string contents = ReadFile(inStream);

    unsigned char digest[EVP_MAX_MD_SIZE];

    const EVP_MD* md = EVP_get_digestbyname("sha256");
    if (md == nullptr)
    {
      LogErrorsSSL();
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
      LogErrorsSSL();
      throw std::runtime_error("EVP_MD_CTX_new()");
    }

    unsigned int digestLen = 0;

    if (not EVP_DigestInit_ex2(mdctx.get(), md, nullptr))
    {
      LogErrorsSSL();
      throw std::runtime_error("EVP_DigestInit_ex2()");
    }

    if (not EVP_DigestUpdate(mdctx.get(), contents.data(), contents.length()))
    {
      LogErrorsSSL();
      throw std::runtime_error("EVP_DigestUpdate()");
    }

    if (not EVP_DigestFinal_ex(mdctx.get(), digest, &digestLen))
    {
      LogErrorsSSL();
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

  // ---------------------------------------------------------------------------

  void Crypt(std::iostream& inStream,
             std::iostream& outStream,
             const AesCipherParams& params)
  {
    std::string input = ReadFile(inStream);
    std::string output;

    cipherIface_.reset(EVP_CIPHER_CTX_new());

    DebugLog("EVP_CipherInit_ex()");

    if (not EVP_CipherInit_ex(cipherIface_.get(),
                              params.cipher,
                              nullptr,
                              params.key.data(),
                              params.iv.data(),
                              params.encrypt))
    {
      LogErrorsSSL();
      throw std::runtime_error("EVP_CipherInit_ex()");
    }

    std::vector<unsigned char> outBuf(input.size() + EVP_MAX_BLOCK_LENGTH);

    int outLen;

    DebugLog("EVP_CipherUpdate()");

    if (not EVP_CipherUpdate(cipherIface_.get(),
                             outBuf.data(),
                             &outLen,
                             (unsigned char*)input.data(),
                             input.size()))
    {
      LogErrorsSSL();
      throw std::runtime_error("EVP_CipherUpdate()");
    }

    DebugLog("outLen = %d", outLen);

    int addLen;

    DebugLog("EVP_CipherFinal_ex()");

    //
    // "Buffer passed to EVP_EncryptFinal() must be after data just encryoted
    // to avoid overwriting it."
    //
    if (not EVP_CipherFinal_ex(cipherIface_.get(),
                               outBuf.data() + outLen,
                               &addLen))
    {
      LogErrorsSSL();
      throw std::runtime_error("EVP_CipherFinal_ex()");
    }

    DebugLog("addLen = %d", addLen);

    int totalLen = outLen + addLen;

    outBuf.resize(totalLen);

    DebugLog("totalLen = %d", totalLen);
    DebugLog("outBuf.size() = %lu", outBuf.size());

    for (int i = 0; i < totalLen; ++i)
    {
      output.push_back(outBuf[i]);
    }

    outStream.write(output.data(), output.size());

    cipherIface_.reset();
  }

  // ---------------------------------------------------------------------------

  void EncryptFile(std::iostream& inStream,
                   std::iostream& outStream,
                   std::string_view password)
  {
    AesCipherParams params = CreateChiperParamsFromPassword(password);
    params.encrypt = 1;

    Crypt(inStream, outStream, params);

    std::println("Successfully encrypted");
  }

  // ---------------------------------------------------------------------------

  void DecryptFile(std::iostream& inStream,
                   std::iostream& outStream,
                   std::string_view password)
  {
    AesCipherParams params = CreateChiperParamsFromPassword(password);
    params.encrypt = 0;

    Crypt(inStream, outStream, params);

    std::println("Successfully decrypted");
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

// =============================================================================

void CryptoGuardCtx::EncryptFile(std::iostream& inStream,
                                 std::iostream& outStream,
                                 std::string_view password)
{
  pImpl_->EncryptFile(inStream, outStream, password);
}

// =============================================================================

void CryptoGuardCtx::DecryptFile(std::iostream& inStream,
                                 std::iostream& outStream,
                                 std::string_view password)
{
  pImpl_->DecryptFile(inStream, outStream, password);
}

}  // namespace CryptoGuard
