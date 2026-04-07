#include "cmd_options.h"

#include <print>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options")
{
  namespace po = boost::program_options;

  desc_.add_options()
    ("help", "Display help message")
    ("command", po::value<std::string>(), "'encrypt', 'decrypt' or 'checksum'")
    ("input", po::value<std::string>(), "Input filename")
    ("output", po::value<std::string>(), "Output filename")
    ("password", po::value<std::string>(), "Encryption password")
  ;
}

// =============================================================================

void ProgramOptions::Parse(int argc, char* argv[])
{
  namespace po = boost::program_options;

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc_), vm);
  po::notify(vm);

  command_ = COMMAND_TYPE::INVALID;

  if (vm.empty() or vm.count("help"))
  {
    command_ = COMMAND_TYPE::HELP;
    std::stringstream ss;
    ss << desc_;
    std::println("{}", ss.str());
    return;
  }

  if (vm.count("command"))
  {
    std::string cmd = vm["command"].as<std::string>();
    if (commandMapping_.count(cmd))
    {
      command_ = commandMapping_.at(cmd);
    }
    else
    {
      error_ = "Invalid command";
      return;
    }
  }

  auto ExtractArg = [this, &vm](const std::string& key, std::string& out)
  {
    if (vm.count(key))
    {
      out = vm[key].as<std::string>();
    }
    else
    {
      command_ = COMMAND_TYPE::INVALID;
      error_ = "Unknown argument";
      return false;
    }

    return true;
  };

  switch (command_)
  {
    case COMMAND_TYPE::ENCRYPT:
    case COMMAND_TYPE::DECRYPT:
    {
      if (not ExtractArg("input", inputFile_))
      {
        error_ = "Bad input file";
        return;
      }

      if (not ExtractArg("output", outputFile_))
      {
        error_ = "Bad output file";
        return;
      }

      if (not ExtractArg("password", password_))
      {
        error_ = "No password";
        return;
      }
    }
    break;

    case COMMAND_TYPE::CHECKSUM:
    {
      if (not ExtractArg("input", inputFile_))
      {
        error_ = "Bad input file";
        return;
      }
    }
    break;

    default:
      break;
  }
}

}  // namespace CryptoGuard
