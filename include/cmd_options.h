#pragma once

#include <boost/program_options.hpp>
#include <string>
#include <unordered_map>

namespace CryptoGuard
{

class ProgramOptions
{
  public:
    ProgramOptions();
    ~ProgramOptions() = default;

    enum class COMMAND_TYPE
    {
      ENCRYPT = 0,
      DECRYPT,
      CHECKSUM,
      HELP,
      INVALID,
      UNDEFINED
    };

    void Parse(int argc, char *argv[]);

    COMMAND_TYPE GetCommand() const { return command_; }
    const std::string& GetInputFile() const { return inputFile_; }
    const std::string& GetOutputFile() const { return outputFile_; }
    const std::string& GetPassword() const { return password_; }
    const std::string& GetError() const { return error_; }

  private:
    COMMAND_TYPE command_ = COMMAND_TYPE::UNDEFINED;
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ =
    {
        { "encrypt" , ProgramOptions::COMMAND_TYPE::ENCRYPT  }
      , { "decrypt" , ProgramOptions::COMMAND_TYPE::DECRYPT  }
      , { "checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM }
    };

    std::string inputFile_;
    std::string outputFile_;
    std::string password_;

    boost::program_options::options_description desc_;

    std::string error_;
};

}  // namespace CryptoGuard
