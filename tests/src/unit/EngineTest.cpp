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
    path = PATH;
    id = ID;
    keyid = KEY;

    std::pair<std::string, std::string> addr("ADDRESS_CONN", ADDR);
    // std::pair<std::string, std::string> port("PORT_CONN", PORT);
    // std::pair<std::string, std::string> user("USERNAME", USER);
    // std::pair<std::string, std::string> pw("PW", PW);
    extraCommands.push_back(addr);
    // extraCommands.push_back(port);
    // extraCommands.push_back(user);
    // extraCommands.push_back(pw);
  }

  DynamicEngine* engine;
  std::string path;
  std::string id;
  std::vector<std::pair<std::string, std::string> > extraCommands;
  std::string keyid;
};

/**
 * @brief Gera e testa engine.
 */
TEST_F(EngineTest, CreateDynamicEngine) {
  ASSERT_EXIT(
  {
    {
      engine = new DynamicEngine(path, id, extraCommands); //!< Objeto para geração da engine.
    }
    exit(0);
  },::testing::ExitedWithCode(0),".*");
}

/**
 * @brief Inicia a engine.
 */
TEST_F(EngineTest, InitEngine) {
  engine = new DynamicEngine(path, id, extraCommands); //!< Objeto para geração da engine.
  ASSERT_EQ(true, engine->testInit());
}

/**
 * @brief Carrega a chave da engine.
 */
TEST_F(EngineTest, LoadEngineKey) {
  engine = new DynamicEngine(path, id, extraCommands); //!< Objeto para geração da engine.

  ASSERT_EXIT(
  {
    {
      KeyPair kpair(engine, keyid);
    }
    exit(0);
  },::testing::ExitedWithCode(0),".*");
}

/**
 * @brief Assina usando a engine.
 */
TEST_F(EngineTest, SignWithEngine) {
  static const long version = 2L;
  RDNSequence rdn = RDNSequence();
  rdn.addEntry(RDNSequence::COUNTRY, "CO");
  rdn.addEntry(RDNSequence::STATE_OR_PROVINCE, "State");
  rdn.addEntry(RDNSequence::LOCALITY, "Locality");
  rdn.addEntry(RDNSequence::ORGANIZATION, "Organization");
  rdn.addEntry(RDNSequence::ORGANIZATION_UNIT, "Organization Unit");
  rdn.addEntry(RDNSequence::COMMON_NAME, "Common Name");

  engine = new DynamicEngine(path, id, extraCommands); //!< Objeto para geração da engine.

  KeyPair kpair(engine, keyid);

  CertificateBuilder certBuilder;
  certBuilder.setSerialNumber(11444);
  certBuilder.setPublicKey(*kpair.getPublicKey());
  certBuilder.setVersion(version);
  certBuilder.setIssuer(rdn);

  ASSERT_EXIT(
  {
    {
      Certificate* cert = certBuilder.sign(*kpair.getPrivateKey(), MessageDigest::SHA256);
    }
    exit(0);
  },::testing::ExitedWithCode(0),".*");
}
