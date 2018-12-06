#include <libcryptosec/DynamicEngine.h>
#include <fstream>
#include "gtest.h"
#include <libcryptosec/KeyPair.h>
#include <libcryptosec/certificate/CertificateBuilder.h>
#include <ostream>

TEST(ENGINE_TEST, setup) {
   std::string path = "";
   std::string id = "";

   std::vector<std::pair<std::string, std::string> > extraCommands;
   std::pair<std::string, std::string> addr("", "");
   std::pair<std::string, std::string> port("", "");
   std::pair<std::string, std::string> user("", "");
   std::pair<std::string, std::string> pw("", "");

  ASSERT_EXIT(
  {
    {
      DynamicEngine engine = DynamicEngine(path, id, extraCommands); //!< Objeto para geração da engine.
    }
    exit(0);
  },::testing::ExitedWithCode(0),".*");
}

TEST(ENGINE_TEST, testInit) {
   std::string path = "";
   std::string id = "";

   std::vector<std::pair<std::string, std::string> > extraCommands;
   std::pair<std::string, std::string> addr("", "");
   std::pair<std::string, std::string> port("", "");
   std::pair<std::string, std::string> user("", "");
   std::pair<std::string, std::string> pw("", "");

  DynamicEngine engine = DynamicEngine(path, id, extraCommands); //!< Objeto para geração da engine.

  ASSERT_EXIT(
  {
    {
      ASSERT_EQ(true, engine.testInit());
    }
    exit(0);
  },::testing::ExitedWithCode(0),".*");
}


TEST(ENGINE_TEST, testSign) {
  // std::string path = "";
  // std::string id = "";
  // std::string keyid = "";
  // static const long version = 2L;
  //
  // std::vector<std::pair<std::string, std::string> > extraCommands;
  // std::pair<std::string, std::string> addr("", "");
  // std::pair<std::string, std::string> port("", "");
  // std::pair<std::string, std::string> user("", "");
  // std::pair<std::string, std::string> pw("", "");

  std::string path = "/home/labsec/Desktop/engine_openhsmd-2.0-static.x86_64.so";
  std::string id = "openhsmd";
  std::string keyid = "chave-2048";
  static const long version = 2L;

  std::vector<std::pair<std::string, std::string> > extraCommands;
  std::pair<std::string, std::string> addr("ADDRESS_CONN", "192.168.66.48");

  RDNSequence rdn = RDNSequence();
  rdn.addEntry(RDNSequence::COUNTRY, "CO");
  rdn.addEntry(RDNSequence::STATE_OR_PROVINCE, "State");
  rdn.addEntry(RDNSequence::LOCALITY, "Locality");
  rdn.addEntry(RDNSequence::ORGANIZATION, "Organization");
  rdn.addEntry(RDNSequence::ORGANIZATION_UNIT, "Organization Unit");
  rdn.addEntry(RDNSequence::COMMON_NAME, "Common Name");

  DynamicEngine engine = DynamicEngine(path, id, extraCommands); //!< Objeto para geração da engine.

  engine.testInit();
  std::cout << "AA" << std::endl;

  KeyPair kpair(&engine, keyid);

  CertificateBuilder certBuilder;
  certBuilder.setSerialNumber(11444);
  certBuilder.setPublicKey(*kpair.getPublicKey());
  certBuilder.setVersion(version);
  certBuilder.setIssuer(rdn);

  ASSERT_EXIT(
  {
    {
      Certificate* cert = certBuilder.sign(*kpair.getPrivateKey(), MessageDigest::SHA512);
    }
    exit(0);
  },::testing::ExitedWithCode(0),".*");
}
