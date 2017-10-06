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
 * @brief Testes unitários de curvas elípticas X962.
 */
class X962EcTest : public ::testing::Test {

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

    void testGenerateX962KeyPair(AsymmetricKey::Curve curve)
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

    // void testSignX962Key(AsymmetricKey::Curve curve, MessageDigest::Algorithm algorithm)
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

    void testSignCertificateX962(AsymmetricKey::Curve curve, MessageDigest::Algorithm algorithm)
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

TEST_F(X962EcTest, SignCertificateEC_X962_PRIME192V1_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_PRIME192V1, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_PRIME192V2_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_PRIME192V2, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_PRIME192V3_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_PRIME192V3, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_PRIME239V1_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_PRIME239V1, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_PRIME239V2_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_PRIME239V2, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_PRIME239V3_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_PRIME239V3, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_PRIME256V1_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_PRIME256V1, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_C2PNB163V1_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_C2PNB163V1, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_C2PNB163V2_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_C2PNB163V2, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_C2PNB163V3_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_C2PNB163V3, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_C2PNB176V1_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_C2PNB176V1, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_C2TNB191V1_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_C2TNB191V1, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_C2TNB191V2_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_C2TNB191V2, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_C2TNB191V3_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_C2TNB191V3, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_C2PNB208W1_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_C2PNB208W1, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_C2TNB239V1_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_C2TNB239V1, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_C2TNB239V2_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_C2TNB239V2, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_C2TNB239V3_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_C2TNB239V3, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_C2PNB272W1_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_C2PNB272W1, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_C2PNB304W1_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_C2PNB304W1, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_C2TNB359V1_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_C2TNB359V1, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_C2PNB368W1_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_C2PNB368W1, MessageDigest::SHA1);
}

TEST_F(X962EcTest, SignCertificateEC_X962_C2TNB431R1_SHA1)
{
    testSignCertificateX962(AsymmetricKey::X962_C2TNB431R1, MessageDigest::SHA1);
}

// Sign

// TEST_F(X962EcTest, SignECKey_X962_PRIME192V1_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_PRIME192V1, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_PRIME192V2_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_PRIME192V2, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_PRIME192V3_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_PRIME192V3, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_PRIME239V1_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_PRIME239V1, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_PRIME239V2_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_PRIME239V2, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_PRIME239V3_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_PRIME239V3, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_PRIME256V1_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_PRIME256V1, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_C2PNB163V1_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_C2PNB163V1, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_C2PNB163V2_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_C2PNB163V2, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_C2PNB163V3_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_C2PNB163V3, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_C2PNB176V1_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_C2PNB176V1, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_C2TNB191V1_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_C2TNB191V1, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_C2TNB191V2_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_C2TNB191V2, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_C2TNB191V3_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_C2TNB191V3, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_C2PNB208W1_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_C2PNB208W1, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_C2TNB239V1_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_C2TNB239V1, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_C2TNB239V2_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_C2TNB239V2, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_C2TNB239V3_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_C2TNB239V3, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_C2PNB272W1_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_C2PNB272W1, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_C2PNB304W1_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_C2PNB304W1, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_C2TNB359V1_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_C2TNB359V1, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_C2PNB368W1_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_C2PNB368W1, MessageDigest::SHA1);
// }

// TEST_F(X962EcTest, SignECKey_X962_C2TNB431R1_SHA1)
// {
//     testSignX962Key(AsymmetricKey::X962_C2TNB431R1, MessageDigest::SHA1);
// }

// GENERATE 

TEST_F(X962EcTest, GenerateECKeyPair_X962_PRIME192V1)
{
 testGenerateX962KeyPair(AsymmetricKey::X962_PRIME192V1);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_PRIME192V2)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_PRIME192V2);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_PRIME192V3)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_PRIME192V3);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_PRIME239V1)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_PRIME239V1);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_PRIME239V2)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_PRIME239V2);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_PRIME239V3)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_PRIME239V3);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_PRIME256V1)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_PRIME256V1);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_C2PNB163V1)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_C2PNB163V1);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_C2PNB163V2)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_C2PNB163V2);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_C2PNB163V3)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_C2PNB163V3);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_C2PNB176V1)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_C2PNB176V1);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_C2TNB191V1)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_C2TNB191V1);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_C2TNB191V2)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_C2TNB191V2);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_C2TNB191V3)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_C2TNB191V3);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_C2PNB208W1)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_C2PNB208W1);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_C2TNB239V1)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_C2TNB239V1);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_C2TNB239V2)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_C2TNB239V2);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_C2TNB239V3)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_C2TNB239V3);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_C2PNB272W1)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_C2PNB272W1);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_C2PNB304W1)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_C2PNB304W1);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_C2TNB359V1)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_C2TNB359V1);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_C2PNB368W1)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_C2PNB368W1);
}

TEST_F(X962EcTest, GenerateECKeyPair_X962_C2TNB431R1)
{
    testGenerateX962KeyPair(AsymmetricKey::X962_C2TNB431R1);
}
