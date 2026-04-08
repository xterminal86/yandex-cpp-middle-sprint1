#include <algorithm>
#include <array>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>
#include <fstream>

#include "cmd_options.h"
#include "crypto_guard_ctx.h"

const std::string kErrOpenFileIn =
  "Failed to open file '{}' for reading - check if it exists "
  "or that you have enough permissions.";

const std::string kErrOpenFileOut =
  "Failed to open file '{}' for writing - do you have enough permissions?";

template <typename... Args>
void PrintError(const std::string& fmtString, Args&&... args)
{
  std::println(
    "{}",
    std::vformat(
      fmtString,
      std::make_format_args(args...)
    )
  );
}

int main(int argc, char *argv[])
{
  try
  {
    CryptoGuard::ProgramOptions options;

    options.Parse(argc, argv);

    CryptoGuard::CryptoGuardCtx cryptoCtx;

    using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

    using FilePtr = std::unique_ptr<
      std::fstream,
      decltype( [](std::fstream* file){ file->close(); } )
    >;

    COMMAND_TYPE cmd = options.GetCommand();
    switch (cmd)
    {
      case COMMAND_TYPE::ENCRYPT:
      case COMMAND_TYPE::DECRYPT:
      {
        FilePtr inFile(
          new std::fstream(options.GetInputFile(),
                           std::ios::in | std::ios::binary)
        );

        if (not inFile->is_open())
        {
          PrintError(kErrOpenFileIn, options.GetInputFile());
          return EXIT_FAILURE;
        }

        FilePtr outFile(
          new std::fstream(options.GetOutputFile(),
                           std::ios::out | std::ios::binary)
        );

        if (not outFile->is_open())
        {
          PrintError(kErrOpenFileOut, options.GetOutputFile());
          return EXIT_FAILURE;
        }

        //
        // Since ecnryption here is symmetric we could've used just one method
        // for both operations (e.g. Crypt()), but since we're given a project
        // template to work in let's leave the outer interface as is at least.
        //
        if (cmd == COMMAND_TYPE::ENCRYPT)
        {
          cryptoCtx.EncryptFile(*inFile.get(),
                                *outFile.get(),
                                options.GetPassword());
        }
        else if (cmd == COMMAND_TYPE::DECRYPT)
        {
          cryptoCtx.DecryptFile(*inFile.get(),
                                *outFile.get(),
                                options.GetPassword());
        }
      }
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
          PrintError(kErrOpenFileIn, options.GetInputFile());
          return EXIT_FAILURE;
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
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}