#include <gtest/gtest.h>

#include "cmd_options.h"

using namespace CryptoGuard;

TEST(ProgramOptions, CommandLine)
{
  ProgramOptions po;

  // ---------------------------------------------------------------------------
  {
    char* argv[] = { "exe", "--help" };
    EXPECT_NO_THROW(po.Parse(2, argv));
    EXPECT_EQ(ProgramOptions::COMMAND_TYPE::HELP, po.GetCommand());
  }
  // ---------------------------------------------------------------------------
  {
    // It seems fucking boost can "guess" command from first character.
    char* argv[] = { "exe", "--h" };
    EXPECT_NO_THROW(po.Parse(2, argv));
    EXPECT_EQ(ProgramOptions::COMMAND_TYPE::HELP, po.GetCommand());
  }
  {
    char* argv[] = { "exe", "--he" };
    EXPECT_NO_THROW(po.Parse(2, argv));
    EXPECT_EQ(ProgramOptions::COMMAND_TYPE::HELP, po.GetCommand());
  }
  {
    char* argv[] = { "exe", "--huj" };
    EXPECT_ANY_THROW(po.Parse(2, argv));
  }
  // ---------------------------------------------------------------------------
  {
    char* argv[] = { "exe", "--unknown" };
    EXPECT_ANY_THROW(po.Parse(2, argv));
  }
  // ---------------------------------------------------------------------------
  {
    char* argv[] = { "exe", "--command" };
    EXPECT_ANY_THROW(po.Parse(2, argv));
  }
  // ---------------------------------------------------------------------------
  {
    char* argv[] = { "exe", "--command=wtf" };
    EXPECT_NO_THROW(po.Parse(2, argv));
    EXPECT_EQ(ProgramOptions::COMMAND_TYPE::INVALID, po.GetCommand());
  }
  // ---------------------------------------------------------------------------
  {
    char* argv[] = { "exe", "--command=encrypt" };
    EXPECT_NO_THROW(po.Parse(2, argv));
    EXPECT_EQ(ProgramOptions::COMMAND_TYPE::INVALID, po.GetCommand());
  }
  // ---------------------------------------------------------------------------
  // succ
  {
    char* argv[] =
    {
        "exe"
      , "--command=encrypt"
      , "--input=in.txt"
      , "--output=out.txt"
      , "--password=secret"
    };
    EXPECT_NO_THROW(po.Parse(5, argv));
    EXPECT_EQ(ProgramOptions::COMMAND_TYPE::ENCRYPT, po.GetCommand());
    EXPECT_STRCASEEQ("in.txt", po.GetInputFile().data());
    EXPECT_STRCASEEQ("out.txt", po.GetOutputFile().data());
    EXPECT_STRCASEEQ("secret", po.GetPassword().data());
  }
  {
    char* argv[] =
    {
      // ./exe --command "encrypt" \
      //       --input "in.txt"    \
      //       --output "out.txt"  \
      //       --password "secret"

        "exe"
      , "--command"
      , "encrypt"
      , "--input"
      , "in.txt"
      , "--output"
      , "out.txt"
      , "--password"
      , "secret"
    };
    EXPECT_NO_THROW(po.Parse(9, argv));
    EXPECT_EQ(ProgramOptions::COMMAND_TYPE::ENCRYPT, po.GetCommand());
    EXPECT_STRCASEEQ("in.txt", po.GetInputFile().data());
    EXPECT_STRCASEEQ("out.txt", po.GetOutputFile().data());
    EXPECT_STRCASEEQ("secret", po.GetPassword().data());
  }
  // ---------------------------------------------------------------------------
  // bad
  {
    char* argv[] =
    {
        "exe"
      , "--command=encrypt"
      , "--input='in.txt'"
      , "--output='out.txt'"
      , "--password='secret'"
      , "--lol"
    };
    EXPECT_ANY_THROW(po.Parse(6, argv));
  }
  {
    char* argv[] =
    {
        "exe"
      , "--command=encrypt"
      , "--output='out.txt'"
      , "--password='secret'"
    };
    EXPECT_NO_THROW(po.Parse(4, argv));
    EXPECT_EQ(ProgramOptions::COMMAND_TYPE::INVALID, po.GetCommand());
  }
  {
    char* argv[] =
    {
        "exe"
      , "--command=encrypt"
      , "--input='in.txt'"
      , "--password='secret'"
    };
    EXPECT_NO_THROW(po.Parse(4, argv));
    EXPECT_EQ(ProgramOptions::COMMAND_TYPE::INVALID, po.GetCommand());
  }
  {
    char* argv[] =
    {
        "exe"
      , "--command=encrypt"
      , "--input='in.txt'"
      , "--output='out.txt'"
    };
    EXPECT_NO_THROW(po.Parse(4, argv));
    EXPECT_EQ(ProgramOptions::COMMAND_TYPE::INVALID, po.GetCommand());
  }
  // ---------------------------------------------------------------------------
  // succ
  {
    char* argv[] =
    {
        "exe"
      , "--command=decrypt"
      , "--input=in.txt"
      , "--output=out.txt"
      , "--password=secret"
    };
    EXPECT_NO_THROW(po.Parse(5, argv));
    EXPECT_EQ(ProgramOptions::COMMAND_TYPE::DECRYPT, po.GetCommand());
  }
  // ---------------------------------------------------------------------------
  {
    char* argv[] =
    {
        "exe"
      , "--command=checksum"
      , "--input=in.txt"
    };
    EXPECT_NO_THROW(po.Parse(3, argv));
    EXPECT_EQ(ProgramOptions::COMMAND_TYPE::CHECKSUM, po.GetCommand());
  }
  {
    char* argv[] =
    {
        "exe"
      , "--command=checksum"
      , "--input=in.txt"
      // ignore extra args
      , "--output=out.txt"
    };
    EXPECT_NO_THROW(po.Parse(4, argv));
    EXPECT_EQ(ProgramOptions::COMMAND_TYPE::CHECKSUM, po.GetCommand());
  }
}