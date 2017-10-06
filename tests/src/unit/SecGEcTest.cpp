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
 * @brief Testes unitários de curvas elípticas SecG.
 */
class SecGEcTest : public ::testing::Test {

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

    void testGenerateSECGKeyPair(AsymmetricKey::Curve curve)
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

    // void testSignSECGKey(AsymmetricKey::Curve curve, MessageDigest::Algorithm algorithm)
    // {
    // 	//Fixture Setup
    // 	char string[6] = "hello";
    // 	ByteArray byteEntry(&string[0]);

    //     MessageDigest md(algorithm);
    //     md.init(algorithm);
    //     md.update(byteEntry);
    //     ByteArray message = md.doFinal();

    // 	ECDSAKeyPair keypair (curve);
    // 	prKey = (ECDSAPrivateKey*) keypair.getPrivateKey();
    // 	pubKey = (ECDSAPublicKey*) keypair.getPublicKey();

    // 	//Exercise SUT
    // 	ByteArray signResult = Signer::sign(*prKey, message, algorithm);

    // 	//Result Verification
    //     ASSERT_TRUE(message.size() > 0);
    //     ASSERT_TRUE(signResult.size() > 0);
    //     ASSERT_TRUE(Signer::verify(*pubKey, signResult, message, algorithm));

    // 	//Fixture Teardown
    // }

    void testSignCertificateSECG(AsymmetricKey::Curve curve, MessageDigest::Algorithm algorithm)
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

TEST_F(SecGEcTest, SignCertificateEC_SECG_SECP160K1_SHA1)
{
    testSignCertificateSECG(AsymmetricKey::SECG_SECP160K1, MessageDigest::SHA1);
}

TEST_F(SecGEcTest, SignCertificateEC_SECG_SECP160R1_SHA1)
{
    testSignCertificateSECG(AsymmetricKey::SECG_SECP160R1, MessageDigest::SHA1);
}

TEST_F(SecGEcTest, SignCertificateEC_SECG_SECP160R2_SHA1)
{
    testSignCertificateSECG(AsymmetricKey::SECG_SECP160R2, MessageDigest::SHA1);
}

TEST_F(SecGEcTest, SignCertificateEC_SECG_SECP192K1_SHA1)
{
    testSignCertificateSECG(AsymmetricKey::SECG_SECP192K1, MessageDigest::SHA1);
}

TEST_F(SecGEcTest, SignCertificateEC_SECG_SECP224K1_SHA1)
{
    testSignCertificateSECG(AsymmetricKey::SECG_SECP224K1, MessageDigest::SHA1);
}

TEST_F(SecGEcTest, SignCertificateEC_SECG_SECP256K1_SHA1)
{
    testSignCertificateSECG(AsymmetricKey::SECG_SECP256K1, MessageDigest::SHA1);
}

TEST_F(SecGEcTest, SignCertificateEC_SECG_SECT163R1_SHA1)
{
    testSignCertificateSECG(AsymmetricKey::SECG_SECT163R1, MessageDigest::SHA1);
}

TEST_F(SecGEcTest, SignCertificateEC_SECG_SECT193R1_SHA1)
{
    testSignCertificateSECG(AsymmetricKey::SECG_SECT193R1, MessageDigest::SHA1);
}

TEST_F(SecGEcTest, SignCertificateEC_SECG_SECT193R2_SHA1)
{
    testSignCertificateSECG(AsymmetricKey::SECG_SECT193R2, MessageDigest::SHA1);
}

TEST_F(SecGEcTest, SignCertificateEC_SECG_SECT239K1_SHA1)
{
    testSignCertificateSECG(AsymmetricKey::SECG_SECT239K1, MessageDigest::SHA1);
}

// Sign

// TEST_F(SecGEcTest, SignECKey_SECG_SECP160K1_SHA1)
// {
//     testSignSECGKey(AsymmetricKey::SECG_SECP160K1, MessageDigest::SHA1);
// }

// TEST_F(SecGEcTest, SignECKey_SECG_SECP160R1_SHA1)
// {
//     testSignSECGKey(AsymmetricKey::SECG_SECP160R1, MessageDigest::SHA1);
// }

// TEST_F(SecGEcTest, SignECKey_SECG_SECP160R2_SHA1)
// {
//     testSignSECGKey(AsymmetricKey::SECG_SECP160R2, MessageDigest::SHA1);
// }

// TEST_F(SecGEcTest, SignECKey_SECG_SECP192K1_SHA1)
// {
//     testSignSECGKey(AsymmetricKey::SECG_SECP192K1, MessageDigest::SHA1);
// }

// TEST_F(SecGEcTest, SignECKey_SECG_SECP224K1_SHA1)
// {
//     testSignSECGKey(AsymmetricKey::SECG_SECP224K1, MessageDigest::SHA1);
// }

// TEST_F(SecGEcTest, SignECKey_SECG_SECP256K1_SHA1)
// {
//     testSignSECGKey(AsymmetricKey::SECG_SECP256K1, MessageDigest::SHA1);
// }

// TEST_F(SecGEcTest, SignECKey_SECG_SECT163R1_SHA1)
// {
//     testSignSECGKey(AsymmetricKey::SECG_SECT163R1, MessageDigest::SHA1);
// }

// TEST_F(SecGEcTest, SignECKey_SECG_SECT193R1_SHA1)
// {
//     testSignSECGKey(AsymmetricKey::SECG_SECT193R1, MessageDigest::SHA1);
// }

// TEST_F(SecGEcTest, SignECKey_SECG_SECT193R2_SHA1)
// {
//     testSignSECGKey(AsymmetricKey::SECG_SECT193R2, MessageDigest::SHA1);
// }

// TEST_F(SecGEcTest, SignECKey_SECG_SECT239K1_SHA1)
// {
//     testSignSECGKey(AsymmetricKey::SECG_SECT239K1, MessageDigest::SHA1);
// }

// GENERATE 

TEST_F(SecGEcTest, GenerateECKeyPair_SECG_SECP160K1)
{
    testGenerateSECGKeyPair(AsymmetricKey::SECG_SECP160K1);
}

TEST_F(SecGEcTest, GenerateECKeyPair_SECG_SECP160R1)
{
    testGenerateSECGKeyPair(AsymmetricKey::SECG_SECP160R1);
}

TEST_F(SecGEcTest, GenerateECKeyPair_SECG_SECP160R2)
{
    testGenerateSECGKeyPair(AsymmetricKey::SECG_SECP160R2);
}

TEST_F(SecGEcTest, GenerateECKeyPair_SECG_SECP192K1)
{
    testGenerateSECGKeyPair(AsymmetricKey::SECG_SECP192K1);
}

TEST_F(SecGEcTest, GenerateECKeyPair_SECG_SECP224K1)
{
    testGenerateSECGKeyPair(AsymmetricKey::SECG_SECP224K1);
}

TEST_F(SecGEcTest, GenerateECKeyPair_SECG_SECP256K1)
{
    testGenerateSECGKeyPair(AsymmetricKey::SECG_SECP256K1);
}

TEST_F(SecGEcTest, GenerateECKeyPair_SECG_SECT163R1)
{
    testGenerateSECGKeyPair(AsymmetricKey::SECG_SECT163R1);
}

TEST_F(SecGEcTest, GenerateECKeyPair_SECG_SECT193R1)
{
    testGenerateSECGKeyPair(AsymmetricKey::SECG_SECT193R1);
}

TEST_F(SecGEcTest, GenerateECKeyPair_SECG_SECT193R2)
{
    testGenerateSECGKeyPair(AsymmetricKey::SECG_SECT193R2);
}

TEST_F(SecGEcTest, GenerateECKeyPair_SECG_SECT239K1)
{
    testGenerateSECGKeyPair(AsymmetricKey::SECG_SECT239K1);
}
