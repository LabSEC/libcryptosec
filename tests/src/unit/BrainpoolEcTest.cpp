#include <libcryptosec/ec/EllipticCurve.h>
#include <libcryptosec/ECDSAKeyPair.h>

#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/certificate/CertificateBuilder.h>

#include <libcryptosec/AsymmetricKey.h>
#include <libcryptosec/Signer.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/MessageDigest.h>

#include <fstream>
#include <stdio.h>

#include "gtest.h"

/**
 * @brief Testes unitários de curvas elípticas Brainpool.
 */
class BrainpoolEcTest : public ::testing::Test {

private:
	ECDSAPrivateKey *prKey;
	ECDSAPublicKey *pubKey;

protected:
	virtual void SetUp()
	{
		MessageDigest::loadMessageDigestAlgorithms();
		SymmetricCipher::loadSymmetricCiphersAlgorithms();
	}

	virtual void TearDown()
	{
		delete(prKey);
		delete(pubKey);
	}

	void testGenerateBrainpoolKeyPair(AsymmetricKey::Curve curve)
	{
		//Fixture Setup

		//Exercise SUT
		ECDSAKeyPair keypair (curve);
		prKey = (ECDSAPrivateKey*) keypair.getPrivateKey();
		pubKey = (ECDSAPublicKey*) keypair.getPublicKey();

		std::string pem = keypair.getPemEncoded();
		ByteArray der = keypair.getDerEncoded();

		std::string pubPem = pubKey->getPemEncoded();
		std::string prPem = prKey->getPemEncoded();

		//Result Verification
		ASSERT_TRUE(keypair.getSize() > 0);
		ASSERT_TRUE(keypair.getSizeBits() > 0);
		ASSERT_TRUE(pem.size() > 0);
		ASSERT_TRUE(der.size() > 0);

		ASSERT_TRUE(pubPem.size() > 0);
		ASSERT_TRUE(pubKey->getSize() > 0);
		ASSERT_TRUE(prPem.size() > 0);
		ASSERT_TRUE(prKey->getSize() > 0);
		
		ASSERT_EQ(keypair.getAlgorithm(), AsymmetricKey::ECDSA);

		//Fixture Teardown
	}

	void testSignCertificateBrainpool(AsymmetricKey::Curve curve, MessageDigest::Algorithm algorithm)
	{
		//Fixture Setup
		CertificateBuilder *certBuilder = new CertificateBuilder();

		ECDSAKeyPair keypair (curve);
		prKey = (ECDSAPrivateKey*) keypair.getPrivateKey();
		pubKey = (ECDSAPublicKey*) keypair.getPublicKey();

		//Exercise SUT
		certBuilder->setPublicKey(*pubKey);
		certBuilder->includeEcdsaParameters();

		Certificate *cert = certBuilder->sign(*prKey, algorithm);
		std::string pem = cert->getPemEncoded();

		//Result Verification
		ASSERT_TRUE(pem.size() > 0);
		ASSERT_TRUE(cert->verify(*pubKey));

		//Fixture Teardown
		delete(cert);
		delete(certBuilder);
	}
};

// CertificateBuilder

TEST_F(BrainpoolEcTest, SignCertificateEC_BRAINPOOL_P160R1_SHA1)
{
	testSignCertificateBrainpool(AsymmetricKey::BRAINPOOL_P160R1, MessageDigest::SHA1);
}

TEST_F(BrainpoolEcTest, SignCertificateEC_BRAINPOOL_P160T1_SHA1)
{
	testSignCertificateBrainpool(AsymmetricKey::BRAINPOOL_P160T1, MessageDigest::SHA1);
}

TEST_F(BrainpoolEcTest, SignCertificateEC_BRAINPOOL_P192R1_SHA1)
{
	testSignCertificateBrainpool(AsymmetricKey::BRAINPOOL_P192R1, MessageDigest::SHA1);
}

TEST_F(BrainpoolEcTest, SignCertificateEC_BRAINPOOL_P224R1_SHA1)
{
	testSignCertificateBrainpool(AsymmetricKey::BRAINPOOL_P224R1, MessageDigest::SHA1);
}

TEST_F(BrainpoolEcTest, SignCertificateEC_BRAINPOOL_P192T1_SHA1)
{
	testSignCertificateBrainpool(AsymmetricKey::BRAINPOOL_P192T1, MessageDigest::SHA1);
}

TEST_F(BrainpoolEcTest, SignCertificateEC_BRAINPOOL_P224T1_SHA1)
{
	testSignCertificateBrainpool(AsymmetricKey::BRAINPOOL_P224T1, MessageDigest::SHA1);
}

TEST_F(BrainpoolEcTest, SignCertificateEC_BRAINPOOL_P256R1_SHA1)
{
	testSignCertificateBrainpool(AsymmetricKey::BRAINPOOL_P256R1, MessageDigest::SHA1);
}

TEST_F(BrainpoolEcTest, SignCertificateEC_BRAINPOOL_P256T1_SHA1)
{
	testSignCertificateBrainpool(AsymmetricKey::BRAINPOOL_P256T1, MessageDigest::SHA1);
}

TEST_F(BrainpoolEcTest, SignCertificateEC_BRAINPOOL_P320R1_SHA1)
{
	testSignCertificateBrainpool(AsymmetricKey::BRAINPOOL_P320R1, MessageDigest::SHA1);
}

TEST_F(BrainpoolEcTest, SignCertificateEC_BRAINPOOL_P320T1_SHA1)
{
	testSignCertificateBrainpool(AsymmetricKey::BRAINPOOL_P320T1, MessageDigest::SHA1);
}

TEST_F(BrainpoolEcTest, SignCertificateEC_BRAINPOOL_P384R1_SHA1)
{
	testSignCertificateBrainpool(AsymmetricKey::BRAINPOOL_P384R1, MessageDigest::SHA1);
}

TEST_F(BrainpoolEcTest, SignCertificateEC_BRAINPOOL_P384T1_SHA1)
{
	testSignCertificateBrainpool(AsymmetricKey::BRAINPOOL_P384T1, MessageDigest::SHA1);
}

TEST_F(BrainpoolEcTest, SignCertificateEC_BRAINPOOL_P512R1_SHA1)
{
	testSignCertificateBrainpool(AsymmetricKey::BRAINPOOL_P512R1, MessageDigest::SHA1);
}

TEST_F(BrainpoolEcTest, SignCertificateEC_BRAINPOOL_P512T1_SHA1)
{
	testSignCertificateBrainpool(AsymmetricKey::BRAINPOOL_P512T1, MessageDigest::SHA1);
}

// Generate 

TEST_F(BrainpoolEcTest, GenerateECKeyPair_BRAINPOOL_P160R1)
{
	testGenerateBrainpoolKeyPair(AsymmetricKey::BRAINPOOL_P160R1);
}

TEST_F(BrainpoolEcTest, GenerateECKeyPair_BRAINPOOL_P160T1)
{
	testGenerateBrainpoolKeyPair(AsymmetricKey::BRAINPOOL_P160T1);
}

TEST_F(BrainpoolEcTest, GenerateECKeyPair_BRAINPOOL_P192R1)
{
	testGenerateBrainpoolKeyPair(AsymmetricKey::BRAINPOOL_P192R1);
}

TEST_F(BrainpoolEcTest, GenerateECKeyPair_BRAINPOOL_P224R1)
{
	testGenerateBrainpoolKeyPair(AsymmetricKey::BRAINPOOL_P224R1);
}

TEST_F(BrainpoolEcTest, GenerateECKeyPair_BRAINPOOL_P192T1)
{
	testGenerateBrainpoolKeyPair(AsymmetricKey::BRAINPOOL_P192T1);
}

TEST_F(BrainpoolEcTest, GenerateECKeyPair_BRAINPOOL_P224T1)
{
	testGenerateBrainpoolKeyPair(AsymmetricKey::BRAINPOOL_P224T1);
}

TEST_F(BrainpoolEcTest, GenerateECKeyPair_BRAINPOOL_P256R1)
{
	testGenerateBrainpoolKeyPair(AsymmetricKey::BRAINPOOL_P256R1);
}

TEST_F(BrainpoolEcTest, GenerateECKeyPair_BRAINPOOL_P256T1)
{
	testGenerateBrainpoolKeyPair(AsymmetricKey::BRAINPOOL_P256T1);
}

TEST_F(BrainpoolEcTest, GenerateECKeyPair_BRAINPOOL_P320R1)
{
	testGenerateBrainpoolKeyPair(AsymmetricKey::BRAINPOOL_P320R1);
}

TEST_F(BrainpoolEcTest, GenerateECKeyPair_BRAINPOOL_P320T1)
{
	testGenerateBrainpoolKeyPair(AsymmetricKey::BRAINPOOL_P320T1);
}

TEST_F(BrainpoolEcTest, GenerateECKeyPair_BRAINPOOL_P384R1)
{
	testGenerateBrainpoolKeyPair(AsymmetricKey::BRAINPOOL_P384R1);
}

TEST_F(BrainpoolEcTest, GenerateECKeyPair_BRAINPOOL_P384T1)
{
	testGenerateBrainpoolKeyPair(AsymmetricKey::BRAINPOOL_P384T1);
}

TEST_F(BrainpoolEcTest, GenerateECKeyPair_BRAINPOOL_P512R1)
{
	testGenerateBrainpoolKeyPair(AsymmetricKey::BRAINPOOL_P512R1);
}

TEST_F(BrainpoolEcTest, GenerateECKeyPair_BRAINPOOL_P512T1)
{
	testGenerateBrainpoolKeyPair(AsymmetricKey::BRAINPOOL_P512T1);
}
