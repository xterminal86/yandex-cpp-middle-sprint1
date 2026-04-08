#include <algorithm>
#include <array>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>
#include <fstream>

#include "cmd_options.h"
#include "crypto_guard_ctx.h"

struct AesCipherParams
{
  // AES-256 key size
  static const size_t KEY_SIZE = 32;
  // AES block size (IV length)
  static const size_t IV_SIZE = 16;
  // Cipher algorithm
  const EVP_CIPHER *cipher = EVP_aes_256_cbc();

  // 1 for encryption, 0 for decryption
  int encrypt;
  std::array<unsigned char, KEY_SIZE> key;  // Encryption key
  std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

AesCipherParams CreateChiperParamsFromPassword(std::string_view password)
{
  AesCipherParams params;
  constexpr std::array<unsigned char, 8> salt =
  { '1', '2', '3', '4', '5', '6', '7', '8' };

  int result = EVP_BytesToKey(
    params.cipher,
    EVP_sha256(),
    salt.data(),
    reinterpret_cast<const unsigned char *>(password.data()),
    password.size(),
    1,
    params.key.data(),
    params.iv.data()
  );

  if (result == 0)
  {
    throw std::runtime_error{"Failed to create a key from password"};
  }

  return params;
}

int main(int argc, char *argv[])
{
  try
  {
    /*
    //
    // OpenSSL пример использования:
    //
    std::string input = "01234567890123456789";
    std::string output;

    OpenSSL_add_all_algorithms();

    auto params = CreateChiperParamsFromPassword("12341234");
    params.encrypt = 1;
    auto *ctx = EVP_CIPHER_CTX_new();

    // Инициализируем cipher
    EVP_CipherInit_ex(ctx,
                      params.cipher,
                      nullptr,
                      params.key.data(),
                      params.iv.data(),
                      params.encrypt);

    std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
    std::vector<unsigned char> inBuf(16);
    int outLen;

    // Обрабатываем первые N символов
    std::copy(input.begin(), std::next(input.begin(), 16), inBuf.begin());
    EVP_CipherUpdate(ctx,
                     outBuf.data(),
                     &outLen,
                     inBuf.data(),
                     static_cast<int>(16));
    for (int i = 0; i < outLen; ++i)
    {
      output.push_back(outBuf[i]);
    }

    // Обрабатываем оставшиеся символы
    std::copy(std::next(input.begin(), 16), input.end(), inBuf.begin());
    EVP_CipherUpdate(ctx,
                     outBuf.data(),
                     &outLen,
                     inBuf.data(),
                     static_cast<int>(input.size() - 16));
    for (int i = 0; i < outLen; ++i)
    {
      output.push_back(outBuf[i]);
    }

    // Заканчиваем работу с cipher
    EVP_CipherFinal_ex(ctx, outBuf.data(), &outLen);
    for (int i = 0; i < outLen; ++i)
    {
      output.push_back(outBuf[i]);
    }
    EVP_CIPHER_CTX_free(ctx);
    std::print("String encoded successfully. Result: '{}'\n\n", output);
    EVP_cleanup();
    //
    // Конец примера
    //
    */

    CryptoGuard::ProgramOptions options;

    options.Parse(argc, argv);

    CryptoGuard::CryptoGuardCtx cryptoCtx;

    using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

    using FilePtr = std::unique_ptr<
      std::fstream,
      decltype( [](std::fstream* file){ file->close(); } )
    >;

    switch (options.GetCommand())
    {
      case COMMAND_TYPE::ENCRYPT:
        std::print("File encoded successfully\n");
        break;

      case COMMAND_TYPE::DECRYPT:
        std::print("File decoded successfully\n");
        break;

      case COMMAND_TYPE::CHECKSUM:
      {
        //
        // 'std::make_unique' uses "default" deleter, so we can't use it here.
        //
        FilePtr inFile(
          new std::fstream(options.GetInputFile(),
                           std::ios::in | std::ios::binary)
        );

        if (not inFile->is_open())
        {
          std::println("Failed to open file '{}' - does it exist?",
                       options.GetInputFile());
          return 1;
        }

        std::string checksum = cryptoCtx.CalculateChecksum(*inFile.get());
        std::println("{}", checksum);
      }
      break;

      case COMMAND_TYPE::HELP:
        break;

      case COMMAND_TYPE::INVALID:
        std::println("{}", options.GetError().data());
        break;

      default:
        throw std::runtime_error{"Unsupported command"};
    }
  }
  catch (const std::exception &e)
  {
    std::print(std::cerr, "Error: {}\n", e.what());
    return 1;
  }

  return 0;
}