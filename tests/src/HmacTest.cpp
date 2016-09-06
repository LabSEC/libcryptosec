#include <libcryptosec/Hmac.h>
#include <fstream>
#include "gtest.h"

/**
 * @brief Testes unitários da classe Hmac.
 */
class HmacTest : public ::testing::Test {

protected:
	virtual void SetUp() {
		hmac = Hmac();
	}

    virtual void TearDown() {
    }

	Hmac hmac; //!< Objeto para geração do Hmac.
	static ByteArray emptyKey; //!< Chave vazia.
	static ByteArray key30bytes; //!< Chave de 30 bytes.
	static ByteArray key63bytes; //!< Chave de 63 bytes.
	static ByteArray key64bytes; //!< Chave de 64 bytes.
	static ByteArray key128bytes; //!< Chave de 128 bytes.
	static ByteArray key129bytes; //!< Chave de 129 bytes.
	static ByteArray key150bytes; //!< Chave de 150 bytes.
	static ByteArray binaryText; //!< Texto binário.
	static ByteArray hexKey40bytes; //!< Chave hexadecimal de 40 bytes.
	static std::vector<ByteArray> plainTexts; //!< Vetor the textos planos.
	static unsigned char hexKey[10]; //!< Chave hexadecimal.
	static ByteArray pText; //!< Texto plano.
};

/*
 * Inicialização das variáveis utilizadas nos testes.
 */
ByteArray HmacTest::emptyKey = ByteArray(new unsigned char[0], 0);
const char stringKey30bytes[] = "XthisIsMyFavoriteKeyOf30bytesX";
ByteArray HmacTest::key30bytes = ByteArray(stringKey30bytes);
const char stringKey63bytes[] = "MyKeyMyKeyMyKeyMyKeyMyKeyMyKeyMyKeyMyKeyMyKeyMyKeyMyKeyMyKey123";
ByteArray HmacTest::key63bytes = ByteArray(stringKey63bytes);
const char stringKey64bytes[] = "Key123Key456Key789Key123Key456Key789Key123Key456Key789Key123Key4";
ByteArray HmacTest::key64bytes = ByteArray(stringKey64bytes);
const char stringKey128bytes[] = "AbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGh";
ByteArray HmacTest::key128bytes = ByteArray(stringKey128bytes);
const char stringKey129bytes[] = "AbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGh"
								"AbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGh1";
ByteArray HmacTest::key129bytes = ByteArray(stringKey129bytes);
const char stringKey150bytes[] = "keyKEYkeyKEYkeyKEYkeyKEYkeyKEYkeyKEYkeyKEYkeyKEYkeyKEYkeyKEYkeyKEY"
		"keyKEYkeyKEYkeyKEYkeyKEYkeyKEYkeyKEYkeyKEYkeyKEYkeyKEYkeyKEYkeyKEYkeyKEYkeyKEYkeyKEY";
ByteArray HmacTest::key150bytes = ByteArray(stringKey150bytes);
unsigned char HmacTest::hexKey[10] = {0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12};
ByteArray HmacTest::hexKey40bytes = ByteArray(&hexKey[0], 10);
const char plainText[] = "plainText";
ByteArray HmacTest::pText(plainText);
std::vector<ByteArray> HmacTest::plainTexts = std::vector<ByteArray>(30, pText);

/**
 * @brief Gera e testa Hmac com o algoritmo sha256 e chave de 30 bytes.
 */
TEST_F(HmacTest, HmacSha256_key30bytes) {
	hmac.init(HmacTest::key30bytes, MessageDigest::SHA256);
	EXPECT_STRCASEEQ("47460fd58266a86d9fe2e9c902ca0c97c58306d3de53fc0596c2df7f251e4d2d",
					hmac.doFinal(HmacTest::plainTexts[0]).toHex().c_str());
}

/**
 * @brief Gera e testa Hmac com o algoritmo sha256 e chave de 64 bytes.
 */
TEST_F(HmacTest, HmacSha256_key64bytes) {
	hmac.init(HmacTest::key64bytes, MessageDigest::SHA256);
	EXPECT_STRCASEEQ("ff6d20b3d45b6c01fe8d07f155be6e94401ebb348fbaf51af8f3d4505d805306",
			hmac.doFinal(HmacTest::plainTexts[0]).toHex().c_str());
}

/**
 * @brief Gera e testa Hmac com o algoritmo sha256 e chave de 150 bytes.
 */
TEST_F(HmacTest, HmacSha256_key150bytes) {
	hmac.init(HmacTest::key150bytes, MessageDigest::SHA256);
	EXPECT_STRCASEEQ("9d448d43be3fde104ca6041fa33a3fd5874cabdb6d37fff8e6d6886529f222cd",
			hmac.doFinal(HmacTest::plainTexts[0]).toHex().c_str());
}

/**
 * @brief Gera e testa Hmac com o algoritmo sha512 e chave de 30 bytes.
 */
TEST_F(HmacTest, HmacSha512_key30bytes) {
	hmac.init(HmacTest::key63bytes, MessageDigest::SHA512);
	EXPECT_STRCASEEQ("60cf29ec2d024968219034b3843bb3f01bca73a1b03e84ab92ab4d12da9b71aa"
					 "fe156c48a1439d4fa25bd230d4b0b05591a7aedfe99b5f2a96ecacce6996ee6a",
					 hmac.doFinal(HmacTest::plainTexts[0]).toHex().c_str());
}

/**
 * @brief Gera e testa Hmac com o algoritmo sha512 e chave de 64 bytes.
 */
TEST_F(HmacTest, HmacSha512_key64bytes) {
	hmac.init(HmacTest::key128bytes, MessageDigest::SHA512);
	EXPECT_STRCASEEQ("eeea8e1889a1ae943f8995de5eaffcefdb35a45d6fb27f8e1c14bc7d5c88cd5e"
					 "35b9c96014d521afddbb479b0a1f9581a64e8f42dd5614deeca147aba6451bf8",
					 hmac.doFinal(plainTexts[0]).toHex().c_str());
}

/**
 * @brief Gera e testa Hmac com o algoritmo sha512 e chave de 150 bytes.
 */
TEST_F(HmacTest, HmacSha512_key150bytes) {
	hmac.init(HmacTest::key129bytes, MessageDigest::SHA512);
	EXPECT_STRCASEEQ("c50e6385aa695a38309e5a6910137e52d53f82b96288de04455cf5ac4fd68567"
					 "9ca604f0405e8f4d0c24327bca3dbb9dd2ba6d14a5ca2a7234892f359c0830bc",
					 hmac.doFinal(HmacTest::plainTexts[0]).toHex().c_str());
}

/**
 * @brief Testa geração do Hmac com algoritmo sha1 e chave binária.
 */
TEST_F(HmacTest, HmacSha1_keyHex10bytes){
	hmac.init(HmacTest::hexKey40bytes, MessageDigest::SHA1);

	EXPECT_STRCASEEQ("C64E6D7457686AE0D25F2B9E5E6FF727C3FDB472",
			hmac.doFinal("Teste").toHex().c_str());
}

/**
 * @brief Teste de exaustivo para geração de Hmac com o algoritmo sha512 e chave de 150 bytes.
 */
TEST_F(HmacTest, HmacSha512Stress_key150bytes) {
	for(int i = 0; i < 100000; i++) {
		hmac.init(HmacTest::key129bytes, MessageDigest::SHA512);
		ASSERT_STRCASEEQ("c50e6385aa695a38309e5a6910137e52d53f82b96288de04455cf5ac4fd68567"
						 "9ca604f0405e8f4d0c24327bca3dbb9dd2ba6d14a5ca2a7234892f359c0830bc",
						 hmac.doFinal(HmacTest::plainTexts[0]).toHex().c_str());
	}
}

/**
 * @brief Gera e testa Hmac com o algoritmo sha512 a partir de um vetor de chaves de 63 bytes.
 */
TEST_F(HmacTest, HmacSha256FromVector_key63bytes) {
	hmac.init(HmacTest::key63bytes, MessageDigest::SHA256);
	hmac.update(HmacTest::plainTexts);
	EXPECT_STRCASEEQ("d98759ff86c0b1b5aa39f6454acbc3a8f3c2fddd97856890d5150aac565eb44b",
			hmac.doFinal().toHex().c_str());
}

/**
 * @brief Gera e testa Hmac com o algoritmo MD5 a partir de uma chave vazia.
 */
TEST_F(HmacTest, HmacMd5_emptyKey) {
	hmac.init(HmacTest::emptyKey, MessageDigest::MD5);
	EXPECT_STRCASEEQ("0d371a986922b57b2247ec55f4b9bea4",
			hmac.doFinal(HmacTest::plainTexts[0]).toHex().c_str());
}

/**
 * @brief Gera e testa Hmac com o algoritmo sha256 a partir de uma chave de 150 bytes e texto vazio.
 */
TEST_F(HmacTest, HmacSha256FromEmptyText_key150bytes) {
	hmac.init(HmacTest::key150bytes, MessageDigest::SHA256);
	EXPECT_STRCASEEQ("0dc9c8bb5048d5219ad0f621387b1bb4a4c06e8c0fe22b24bc1dcce2a1b61677",
			hmac.doFinal("").toHex().c_str());
}

/**
 * @brief Gera e testa Hmac com o algoritmo sha1 de um arquivo binário e chave de 63 bytes.
 */
TEST_F(HmacTest, HmacSha1FromBinaryFile_key63bytes) {
	fstream file ("files/binaryFile", ios::in|ios::binary|ios::ate);
	if(file.is_open()){
		file.seekg (0, file.end);
		int length = file.tellg();
		file.seekg (0, file.beg);

		unsigned char * memblock = new unsigned char [length];

		file.read ((char*)memblock, length);
		file.close();

		hmac.init(HmacTest::key63bytes, MessageDigest::SHA1);
		ByteArray b(memblock, length);
		delete[] memblock;
		EXPECT_STRCASEEQ("2dce9d5c64b7879fb52656953ae128a1eb2cd148",
				hmac.doFinal(b).toHex().c_str());

	}else{
		FAIL();
	}
}

/**
 * @brief Testa geração do Hmac com texto vazio, sem chave, sem inicialização e através do .doFinal().
 */
TEST_F(HmacTest, HmacNoInitializationAndDoFinal) {
	EXPECT_THROW(hmac.doFinal(), InvalidStateException);
}

/**
 * @brief Testa geração do Hmac com texto vazio, sem chave, sem inicialização e através do .doUpdate().
 */
TEST_F(HmacTest, HmacNoInitializationAndUpdate) {
	EXPECT_THROW(hmac.update(""), InvalidStateException);
}

/**
 * @brief Testa geração do Hmac com algoritmo sha256, inicializando o hmac duas vezes com algoritmo e chaves diferentes.
 */
TEST_F(HmacTest, HmacInitializationTwice) {
	hmac.init(HmacTest::key30bytes, MessageDigest::SHA256);
	hmac.init(HmacTest::key64bytes, MessageDigest::SHA256);
	EXPECT_STRCASEEQ("ff6d20b3d45b6c01fe8d07f155be6e94401ebb348fbaf51af8f3d4505d805306",
			hmac.doFinal(plainTexts[0]).toHex().c_str());
}

/**
 * @brief Testa geração do Hmac com algoritmo sha256, com chave de 64 bytes, sem atualizar e através do .doFinal().
 */
TEST_F(HmacTest, HmacNoUpdateAndDoFinal) {
	hmac.init(HmacTest::key64bytes, MessageDigest::SHA256);
	EXPECT_THROW(hmac.doFinal(), InvalidStateException);
}

/**
 * @brief Testa geração do Hmac com algoritmo sha256, utilizando .doFinal() duas vezes seguidas (sem inicializar a segunda vez).
 */
TEST_F(HmacTest, HmacDoFinalTwice) {
	hmac.init(HmacTest::key30bytes, MessageDigest::SHA256);
	hmac.doFinal("");
	EXPECT_THROW(hmac.doFinal(), InvalidStateException);
}
