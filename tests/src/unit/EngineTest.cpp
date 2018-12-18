//Compile only if engine is defined
#ifdef ENGINE_COMP

#include <libcryptosec/DynamicEngine.h>
#include <fstream>
#include "gtest.h"
#include <libcryptosec/KeyPair.h>
#include <libcryptosec/certificate/CertificateBuilder.h>
#include <ostream>

#define PATH ""
#define ID ""
#define ADDR ""
#define PORT ""
#define USER ""
#define PW ""
#define KEY ""

/**
 * @brief Testes unitários da classe Engine.
 */
class EngineTest : public ::testing::Test {

protected:

  virtual void SetUp() {
	ENGINE_load_dynamic();
	OpenSSL_add_all_algorithms();
    path = PATH;
    id = ID;
    keyid = KEY;

    std::pair<std::string, std::string> addr("ADDRESS_CONN", ADDR);
    //std::pair<std::string, std::string> port("PORT_CONN", PORT);
    // std::pair<std::string, std::string> user("USERNAME", USER);
    // std::pair<std::string, std::string> pw("PW", PW);
    extraCommands.push_back(addr);
    //extraCommands.push_back(port);
    // extraCommands.push_back(user);
    // extraCommands.push_back(pw);
  }

  virtual void TearDown() {
	EVP_cleanup();
  }

  std::string path;
  std::string id;
  std::vector<std::pair<std::string, std::string> > extraCommands;
  std::string keyid;
};

typedef EngineTest EngineDeathTest;


/*
 *############################### DEATH TESTS! ###############################
 */

/**
 * @brief FynamicEngine Constructor death test.
 */
TEST_F(EngineDeathTest, CreateDynamicEngine) {
  testing::FLAGS_gtest_death_test_style="threadsafe";
  ASSERT_EXIT(
  {
    {DynamicEngine engine(path, id, extraCommands);} //!< Objeto para geração da engine.
    exit(0);
  },::testing::ExitedWithCode(0),".*");
}

/**
 * @brief Engine init/finish (connection) death test.
 */
TEST_F(EngineDeathTest, InitEngine) {
  testing::FLAGS_gtest_death_test_style="threadsafe";
  DynamicEngine engine(path, id, extraCommands); //!< Objeto para geração da engine.
  ASSERT_EXIT(
  {
	{engine.testInit();}
    exit(0);
  },::testing::ExitedWithCode(0),".*");
}

/**
 * @brief Engine load key death test.
 */
TEST_F(EngineDeathTest, LoadEngineKey) {
  testing::FLAGS_gtest_death_test_style="threadsafe";
  DynamicEngine engine(path, id, extraCommands); //!< Objeto para geração da engine.
  ASSERT_EXIT(
  {
    { try {KeyPair kpair(&engine, keyid);} catch (...){};}
    exit(0);
  },::testing::ExitedWithCode(0),".*");
}

/**
 * @brief Assina usando a engine.
 */
TEST_F(EngineDeathTest, SignWithEngine) {
  testing::FLAGS_gtest_death_test_style="threadsafe";
  static const long version = 2L;
  RDNSequence rdn = RDNSequence();
  rdn.addEntry(RDNSequence::COUNTRY, "CO");
  rdn.addEntry(RDNSequence::STATE_OR_PROVINCE, "State");
  rdn.addEntry(RDNSequence::LOCALITY, "Locality");
  rdn.addEntry(RDNSequence::ORGANIZATION, "Organization");
  rdn.addEntry(RDNSequence::ORGANIZATION_UNIT, "Organization Unit");
  rdn.addEntry(RDNSequence::COMMON_NAME, "Common Name");

  DynamicEngine engine(path, id, extraCommands); //!< Objeto para geração da engine.

  KeyPair kpair(&engine, keyid);

  CertificateBuilder certBuilder;
  certBuilder.setSerialNumber(11444);
  certBuilder.setPublicKey(*kpair.getPublicKey());
  certBuilder.setVersion(version);
  certBuilder.setIssuer(rdn);

  ASSERT_EXIT(
  {
    {try {Certificate* cert = certBuilder.sign(*kpair.getPrivateKey(), MessageDigest::SHA256);} catch (...){};}
    exit(0);
  },::testing::ExitedWithCode(0),".*");
}

/*
 *############################### NORMAL TESTS! ###############################
 */

/**
 * @brief Inicia a engine.
 */
TEST_F(EngineTest, InitEngine) {
  testing::FLAGS_gtest_death_test_style="threadsafe";
  DynamicEngine engine(path, id, extraCommands); //!< Objeto para geração da engine.
  bool check = false;
  EXPECT_NO_THROW(
    check = engine.testInit();
  );
  ASSERT_EQ(true, check);
}

/**
 * @brief Engine load key test.
 */
TEST_F(EngineTest, LoadEngineKey) {
  testing::FLAGS_gtest_death_test_style="threadsafe";
  DynamicEngine engine(path, id, extraCommands); //!< Objeto para geração da engine.
  try {
    KeyPair kpair(&engine, keyid);
  } catch(LibCryptoSecException& e) {
    FAIL() << "with message exception msg: " <<  e.getMessage();
  }
}

/**
 * @brief Assina usando a engine.
 */
TEST_F(EngineTest, SignWithEngine) {
  testing::FLAGS_gtest_death_test_style="threadsafe";
  static const long version = 2L;
  RDNSequence rdn = RDNSequence();
  rdn.addEntry(RDNSequence::COUNTRY, "CO");
  rdn.addEntry(RDNSequence::STATE_OR_PROVINCE, "State");
  rdn.addEntry(RDNSequence::LOCALITY, "Locality");
  rdn.addEntry(RDNSequence::ORGANIZATION, "Organization");
  rdn.addEntry(RDNSequence::ORGANIZATION_UNIT, "Organization Unit");
  rdn.addEntry(RDNSequence::COMMON_NAME, "Common Name");

  DynamicEngine engine(path, id, extraCommands); //!< Objeto para geração da engine.

  KeyPair kpair(&engine, keyid);

  CertificateBuilder certBuilder;
  certBuilder.setSerialNumber(11444);
  certBuilder.setPublicKey(*kpair.getPublicKey());
  certBuilder.setVersion(version);
  certBuilder.setIssuer(rdn);
  Certificate* cert;
  EXPECT_NO_THROW(
    cert = certBuilder.sign(*kpair.getPrivateKey(), MessageDigest::SHA256);
  );
  //TODO Verify signature?
}

#endif
