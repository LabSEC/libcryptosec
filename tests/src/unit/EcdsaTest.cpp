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
#include <gtest/gtest.h>

/**
 * @brief Testes unitários de curvas elípticas NistSecG.
 */
class EcdsaTest : public ::testing::Test {

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

	void testGenerateKeyPair(AsymmetricKey::Curve curve)
	{
		//Fixture Setup
		EXPECT_NO_THROW(
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
		);
		//Fixture Teardown
	}

	void testSignCertificate(AsymmetricKey::Curve curve, MessageDigest::Algorithm algorithm)
	{
		EXPECT_NO_THROW(
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
		);
	}
};

/*
 * FIPS Openssl has only a few named curves available.
 * $openssl ecparam -list_curves
 * secp256k1 : SECG curve over a 256 bit prime field
 * secp384r1 : NIST/SECG curve over a 384 bit prime field
 * secp521r1 : NIST/SECG curve over a 521 bit prime field
 * prime256v1: X9.62/SECG curve over a 256 bit prime field
 */

/* FIPS ONLY GENERATE */
TEST_F(EcdsaTest, GenerateECKeyPair_SECG_SECP256K1)
{
	testGenerateKeyPair(AsymmetricKey::SECG_SECP256K1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_NISTSECG_SECP384R1)
{
	testGenerateKeyPair(AsymmetricKey::NISTSECG_SECP384R1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_NISTSECG_SECP521R1)
{
	testGenerateKeyPair(AsymmetricKey::NISTSECG_SECP521R1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_PRIME256V1)
{
	testGenerateKeyPair(AsymmetricKey::X962_PRIME256V1);
}

/* FIPS ONLY SIGN */

TEST_F(EcdsaTest, SignCertificateEC_SECG_SECP256K1_SHA1)
{
	testSignCertificate(AsymmetricKey::SECG_SECP256K1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_NISTSECG_SECP384R1_SHA1)
{
	testSignCertificate(AsymmetricKey::NISTSECG_SECP384R1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_NISTSECG_SECP521R1_SHA1)
{
	testSignCertificate(AsymmetricKey::NISTSECG_SECP521R1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_PRIME256V1_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_PRIME256V1, MessageDigest::SHA1);
}

#ifndef FIPS

/* NIST GENERATE */ 

TEST_F(EcdsaTest, GenerateECKeyPair_NISTSECG_SECP224R1)
{
	testGenerateKeyPair(AsymmetricKey::NISTSECG_SECP224R1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_NISTSECG_SECT163K1)
{
	testGenerateKeyPair(AsymmetricKey::NISTSECG_SECT163K1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_NISTSECG_SECT163R2)
{
	testGenerateKeyPair(AsymmetricKey::NISTSECG_SECT163R2);
}

TEST_F(EcdsaTest, GenerateECKeyPair_NISTSECG_SECT233K1)
{
	testGenerateKeyPair(AsymmetricKey::NISTSECG_SECT233K1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_NISTSECG_SECT233R1)
{
	testGenerateKeyPair(AsymmetricKey::NISTSECG_SECT233R1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_NISTSECG_SECT283K1)
{
	testGenerateKeyPair(AsymmetricKey::NISTSECG_SECT283K1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_NISTSECG_SECT283R1)
{
	testGenerateKeyPair(AsymmetricKey::NISTSECG_SECT283R1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_NISTSECG_SECT409K1)
{
	testGenerateKeyPair(AsymmetricKey::NISTSECG_SECT409K1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_NISTSECG_SECT409R1)
{
	testGenerateKeyPair(AsymmetricKey::NISTSECG_SECT409R1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_NISTSECG_SECT571K1)
{
	testGenerateKeyPair(AsymmetricKey::NISTSECG_SECT571K1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_NISTSECG_SECT571R1)
{
	testGenerateKeyPair(AsymmetricKey::NISTSECG_SECT571R1);
}

/* NIST SIGN */

TEST_F(EcdsaTest, SignCertificateEC_NISTSECG_SECP224R1_SHA1)
{
	testSignCertificate(AsymmetricKey::NISTSECG_SECP224R1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_NISTSECG_SECT163K1_SHA1)
{
	testSignCertificate(AsymmetricKey::NISTSECG_SECT163K1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_NISTSECG_SECT163R2_SHA1)
{
	testSignCertificate(AsymmetricKey::NISTSECG_SECT163R2, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_NISTSECG_SECT233K1_SHA1)
{
	testSignCertificate(AsymmetricKey::NISTSECG_SECT233K1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_NISTSECG_SECT233R1_SHA1)
{
	testSignCertificate(AsymmetricKey::NISTSECG_SECT233R1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_NISTSECG_SECT283K1_SHA1)
{
	testSignCertificate(AsymmetricKey::NISTSECG_SECT283K1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_NISTSECG_SECT283R1_SHA1)
{
	testSignCertificate(AsymmetricKey::NISTSECG_SECT283R1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_NISTSECG_SECT409K1_SHA1)
{
	testSignCertificate(AsymmetricKey::NISTSECG_SECT409K1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_NISTSECG_SECT409R1_SHA1)
{
	testSignCertificate(AsymmetricKey::NISTSECG_SECT409R1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_NISTSECG_SECT571K1_SHA1)
{
	testSignCertificate(AsymmetricKey::NISTSECG_SECT571K1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_NISTSECG_SECT571R1_SHA1)
{
	testSignCertificate(AsymmetricKey::NISTSECG_SECT571R1, MessageDigest::SHA1);
}

/* BRAINPOOL GENERATE*/ 

TEST_F(EcdsaTest, GenerateECKeyPair_BRAINPOOL_P160R1)
{
	testGenerateKeyPair(AsymmetricKey::BRAINPOOL_P160R1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_BRAINPOOL_P160T1)
{
	testGenerateKeyPair(AsymmetricKey::BRAINPOOL_P160T1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_BRAINPOOL_P192R1)
{
	testGenerateKeyPair(AsymmetricKey::BRAINPOOL_P192R1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_BRAINPOOL_P224R1)
{
	testGenerateKeyPair(AsymmetricKey::BRAINPOOL_P224R1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_BRAINPOOL_P192T1)
{
	testGenerateKeyPair(AsymmetricKey::BRAINPOOL_P192T1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_BRAINPOOL_P224T1)
{
	testGenerateKeyPair(AsymmetricKey::BRAINPOOL_P224T1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_BRAINPOOL_P256R1)
{
	testGenerateKeyPair(AsymmetricKey::BRAINPOOL_P256R1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_BRAINPOOL_P256T1)
{
	testGenerateKeyPair(AsymmetricKey::BRAINPOOL_P256T1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_BRAINPOOL_P320R1)
{
	testGenerateKeyPair(AsymmetricKey::BRAINPOOL_P320R1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_BRAINPOOL_P320T1)
{
	testGenerateKeyPair(AsymmetricKey::BRAINPOOL_P320T1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_BRAINPOOL_P384R1)
{
	testGenerateKeyPair(AsymmetricKey::BRAINPOOL_P384R1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_BRAINPOOL_P384T1)
{
	testGenerateKeyPair(AsymmetricKey::BRAINPOOL_P384T1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_BRAINPOOL_P512R1)
{
	testGenerateKeyPair(AsymmetricKey::BRAINPOOL_P512R1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_BRAINPOOL_P512T1)
{
	testGenerateKeyPair(AsymmetricKey::BRAINPOOL_P512T1);
}

/* BRAINPOOL SIGN*/

TEST_F(EcdsaTest, SignCertificateEC_BRAINPOOL_P160R1_SHA1)
{
	testSignCertificate(AsymmetricKey::BRAINPOOL_P160R1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_BRAINPOOL_P160T1_SHA1)
{
	testSignCertificate(AsymmetricKey::BRAINPOOL_P160T1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_BRAINPOOL_P192R1_SHA1)
{
	testSignCertificate(AsymmetricKey::BRAINPOOL_P192R1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_BRAINPOOL_P224R1_SHA1)
{
	testSignCertificate(AsymmetricKey::BRAINPOOL_P224R1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_BRAINPOOL_P192T1_SHA1)
{
	testSignCertificate(AsymmetricKey::BRAINPOOL_P192T1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_BRAINPOOL_P224T1_SHA1)
{
	testSignCertificate(AsymmetricKey::BRAINPOOL_P224T1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_BRAINPOOL_P256R1_SHA1)
{
	testSignCertificate(AsymmetricKey::BRAINPOOL_P256R1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_BRAINPOOL_P256T1_SHA1)
{
	testSignCertificate(AsymmetricKey::BRAINPOOL_P256T1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_BRAINPOOL_P320R1_SHA1)
{
	testSignCertificate(AsymmetricKey::BRAINPOOL_P320R1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_BRAINPOOL_P320T1_SHA1)
{
	testSignCertificate(AsymmetricKey::BRAINPOOL_P320T1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_BRAINPOOL_P384R1_SHA1)
{
	testSignCertificate(AsymmetricKey::BRAINPOOL_P384R1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_BRAINPOOL_P384T1_SHA1)
{
	testSignCertificate(AsymmetricKey::BRAINPOOL_P384T1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_BRAINPOOL_P512R1_SHA1)
{
	testSignCertificate(AsymmetricKey::BRAINPOOL_P512R1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_BRAINPOOL_P512T1_SHA1)
{
	testSignCertificate(AsymmetricKey::BRAINPOOL_P512T1, MessageDigest::SHA1);
}

/* SEC GENERATE */

TEST_F(EcdsaTest, GenerateECKeyPair_SECG_SECP160K1)
{
	testGenerateKeyPair(AsymmetricKey::SECG_SECP160K1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_SECG_SECP160R1)
{
	testGenerateKeyPair(AsymmetricKey::SECG_SECP160R1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_SECG_SECP160R2)
{
	testGenerateKeyPair(AsymmetricKey::SECG_SECP160R2);
}

TEST_F(EcdsaTest, GenerateECKeyPair_SECG_SECP192K1)
{
	testGenerateKeyPair(AsymmetricKey::SECG_SECP192K1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_SECG_SECP224K1)
{
	testGenerateKeyPair(AsymmetricKey::SECG_SECP224K1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_SECG_SECT163R1)
{
	testGenerateKeyPair(AsymmetricKey::SECG_SECT163R1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_SECG_SECT193R1)
{
	testGenerateKeyPair(AsymmetricKey::SECG_SECT193R1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_SECG_SECT193R2)
{
	testGenerateKeyPair(AsymmetricKey::SECG_SECT193R2);
}

TEST_F(EcdsaTest, GenerateECKeyPair_SECG_SECT239K1)
{
	testGenerateKeyPair(AsymmetricKey::SECG_SECT239K1);
}

/* SEC SIGN*/

TEST_F(EcdsaTest, SignCertificateEC_SECG_SECP160K1_SHA1)
{
	testSignCertificate(AsymmetricKey::SECG_SECP160K1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_SECG_SECP160R1_SHA1)
{
	testSignCertificate(AsymmetricKey::SECG_SECP160R1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_SECG_SECP160R2_SHA1)
{
	testSignCertificate(AsymmetricKey::SECG_SECP160R2, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_SECG_SECP192K1_SHA1)
{
	testSignCertificate(AsymmetricKey::SECG_SECP192K1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_SECG_SECP224K1_SHA1)
{
	testSignCertificate(AsymmetricKey::SECG_SECP224K1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_SECG_SECT163R1_SHA1)
{
	testSignCertificate(AsymmetricKey::SECG_SECT163R1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_SECG_SECT193R1_SHA1)
{
	testSignCertificate(AsymmetricKey::SECG_SECT193R1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_SECG_SECT193R2_SHA1)
{
	testSignCertificate(AsymmetricKey::SECG_SECT193R2, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_SECG_SECT239K1_SHA1)
{
	testSignCertificate(AsymmetricKey::SECG_SECT239K1, MessageDigest::SHA1);
}

/* PRIME GENERATE */

TEST_F(EcdsaTest, GenerateECKeyPair_X962_PRIME192V1)
{
 testGenerateKeyPair(AsymmetricKey::X962_PRIME192V1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_PRIME192V2)
{
	testGenerateKeyPair(AsymmetricKey::X962_PRIME192V2);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_PRIME192V3)
{
	testGenerateKeyPair(AsymmetricKey::X962_PRIME192V3);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_PRIME239V1)
{
	testGenerateKeyPair(AsymmetricKey::X962_PRIME239V1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_PRIME239V2)
{
	testGenerateKeyPair(AsymmetricKey::X962_PRIME239V2);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_PRIME239V3)
{
	testGenerateKeyPair(AsymmetricKey::X962_PRIME239V3);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_C2PNB163V1)
{
	testGenerateKeyPair(AsymmetricKey::X962_C2PNB163V1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_C2PNB163V2)
{
	testGenerateKeyPair(AsymmetricKey::X962_C2PNB163V2);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_C2PNB163V3)
{
	testGenerateKeyPair(AsymmetricKey::X962_C2PNB163V3);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_C2PNB176V1)
{
	testGenerateKeyPair(AsymmetricKey::X962_C2PNB176V1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_C2TNB191V1)
{
	testGenerateKeyPair(AsymmetricKey::X962_C2TNB191V1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_C2TNB191V2)
{
	testGenerateKeyPair(AsymmetricKey::X962_C2TNB191V2);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_C2TNB191V3)
{
	testGenerateKeyPair(AsymmetricKey::X962_C2TNB191V3);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_C2PNB208W1)
{
	testGenerateKeyPair(AsymmetricKey::X962_C2PNB208W1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_C2TNB239V1)
{
	testGenerateKeyPair(AsymmetricKey::X962_C2TNB239V1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_C2TNB239V2)
{
	testGenerateKeyPair(AsymmetricKey::X962_C2TNB239V2);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_C2TNB239V3)
{
	testGenerateKeyPair(AsymmetricKey::X962_C2TNB239V3);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_C2PNB272W1)
{
	testGenerateKeyPair(AsymmetricKey::X962_C2PNB272W1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_C2PNB304W1)
{
	testGenerateKeyPair(AsymmetricKey::X962_C2PNB304W1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_C2TNB359V1)
{
	testGenerateKeyPair(AsymmetricKey::X962_C2TNB359V1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_C2PNB368W1)
{
	testGenerateKeyPair(AsymmetricKey::X962_C2PNB368W1);
}

TEST_F(EcdsaTest, GenerateECKeyPair_X962_C2TNB431R1)
{
	testGenerateKeyPair(AsymmetricKey::X962_C2TNB431R1);
}

/* PRIME SIGN*/

TEST_F(EcdsaTest, SignCertificateEC_X962_PRIME192V1_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_PRIME192V1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_PRIME192V2_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_PRIME192V2, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_PRIME192V3_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_PRIME192V3, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_PRIME239V1_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_PRIME239V1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_PRIME239V2_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_PRIME239V2, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_PRIME239V3_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_PRIME239V3, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_C2PNB163V1_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_C2PNB163V1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_C2PNB163V2_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_C2PNB163V2, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_C2PNB163V3_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_C2PNB163V3, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_C2PNB176V1_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_C2PNB176V1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_C2TNB191V1_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_C2TNB191V1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_C2TNB191V2_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_C2TNB191V2, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_C2TNB191V3_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_C2TNB191V3, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_C2PNB208W1_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_C2PNB208W1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_C2TNB239V1_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_C2TNB239V1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_C2TNB239V2_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_C2TNB239V2, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_C2TNB239V3_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_C2TNB239V3, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_C2PNB272W1_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_C2PNB272W1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_C2PNB304W1_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_C2PNB304W1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_C2TNB359V1_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_C2TNB359V1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_C2PNB368W1_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_C2PNB368W1, MessageDigest::SHA1);
}

TEST_F(EcdsaTest, SignCertificateEC_X962_C2TNB431R1_SHA1)
{
	testSignCertificate(AsymmetricKey::X962_C2TNB431R1, MessageDigest::SHA1);
}

#endif /* NON FIPS TEST CASES */
