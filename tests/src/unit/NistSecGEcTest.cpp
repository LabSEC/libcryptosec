#include <libcryptosec/ec/EllipticCurve.h>
#include <libcryptosec/ECDSAKeyPair.h>

#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/Pkcs7SignedDataBuilder.h>
#include <libcryptosec/Pkcs7SignedData.h>

#include <libcryptosec/AsymmetricKey.h>
#include <libcryptosec/Signer.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/MessageDigest.h>

#include <fstream>
#include <stdio.h>

#include "gtest.h"

/**
 * @brief Testes unitários de curvas elípticas NistSecG.
 */
class NistSecGEcTest : public ::testing::Test {

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

    void testGenerateNISTSECGKeyPair(AsymmetricKey::Curve curve)
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

    // void testSignNISTSECGKey(AsymmetricKey::Curve curve, MessageDigest::Algorithm algorithm)
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

    void testSignCertificateNISTSECG(AsymmetricKey::Curve curve, MessageDigest::Algorithm algorithm)
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

    // void testSignPKCS7NISTSECG(AsymmetricKey::Curve curve, MessageDigest::Algorithm algorithm)
    // {
    //     //Fixture Setup
    //     CertificateBuilder *certBuilder = new CertificateBuilder();

    //     ECDSAKeyPair keypair (curve);
    //     prKey = (ECDSAPrivateKey*) keypair.getPrivateKey();
    //     pubKey = (ECDSAPublicKey*) keypair.getPublicKey();

    //     certBuilder->setPublicKey(*pubKey);
    //     certBuilder->includeEcdsaParameters();

    //     Certificate *cert = certBuilder->sign(*prKey, algorithm);

    //     std::ifstream is ("files/pkcs7In", std::ifstream::in);
    //     std::ofstream os ("files/pkcs7Out", std::ifstream::out);

    //     //Exercise SUT
    //     Pkcs7SignedDataBuilder *pkcs7S =  new Pkcs7SignedDataBuilder(algorithm, *cert, *prKey, true);
    //     pkcs7S->init(algorithm, *cert, *prKey, true);
    //     pkcs7S->doFinal(&is, &os);
        
    //     //Result Verification

    //     //Fixture Teardown
    //     is.close();
    //     os.close();
    //     delete(pkcs7S);
    //     delete(cert);
    //     delete(certBuilder);
    // }
};

// CertificateBuilder

TEST_F(NistSecGEcTest, SignCertificateEC_NISTSECG_SECP224R1_SHA1)
{
    testSignCertificateNISTSECG(AsymmetricKey::NISTSECG_SECP224R1, MessageDigest::SHA1);
}

TEST_F(NistSecGEcTest, SignCertificateEC_NISTSECG_SECP384R1_SHA1)
{
    testSignCertificateNISTSECG(AsymmetricKey::NISTSECG_SECP384R1, MessageDigest::SHA1);
}

TEST_F(NistSecGEcTest, SignCertificateEC_NISTSECG_SECP521R1_SHA1)
{
    testSignCertificateNISTSECG(AsymmetricKey::NISTSECG_SECP521R1, MessageDigest::SHA1);
}

TEST_F(NistSecGEcTest, SignCertificateEC_NISTSECG_SECT163K1_SHA1)
{
    testSignCertificateNISTSECG(AsymmetricKey::NISTSECG_SECT163K1, MessageDigest::SHA1);
}

TEST_F(NistSecGEcTest, SignCertificateEC_NISTSECG_SECT163R2_SHA1)
{
    testSignCertificateNISTSECG(AsymmetricKey::NISTSECG_SECT163R2, MessageDigest::SHA1);
}

TEST_F(NistSecGEcTest, SignCertificateEC_NISTSECG_SECT233K1_SHA1)
{
    testSignCertificateNISTSECG(AsymmetricKey::NISTSECG_SECT233K1, MessageDigest::SHA1);
}

TEST_F(NistSecGEcTest, SignCertificateEC_NISTSECG_SECT233R1_SHA1)
{
    testSignCertificateNISTSECG(AsymmetricKey::NISTSECG_SECT233R1, MessageDigest::SHA1);
}

TEST_F(NistSecGEcTest, SignCertificateEC_NISTSECG_SECT283K1_SHA1)
{
    testSignCertificateNISTSECG(AsymmetricKey::NISTSECG_SECT283K1, MessageDigest::SHA1);
}

TEST_F(NistSecGEcTest, SignCertificateEC_NISTSECG_SECT283R1_SHA1)
{
    testSignCertificateNISTSECG(AsymmetricKey::NISTSECG_SECT283R1, MessageDigest::SHA1);
}

TEST_F(NistSecGEcTest, SignCertificateEC_NISTSECG_SECT409K1_SHA1)
{
    testSignCertificateNISTSECG(AsymmetricKey::NISTSECG_SECT409K1, MessageDigest::SHA1);
}

TEST_F(NistSecGEcTest, SignCertificateEC_NISTSECG_SECT409R1_SHA1)
{
    testSignCertificateNISTSECG(AsymmetricKey::NISTSECG_SECT409R1, MessageDigest::SHA1);
}

TEST_F(NistSecGEcTest, SignCertificateEC_NISTSECG_SECT571K1_SHA1)
{
    testSignCertificateNISTSECG(AsymmetricKey::NISTSECG_SECT571K1, MessageDigest::SHA1);
}

TEST_F(NistSecGEcTest, SignCertificateEC_NISTSECG_SECT571R1_SHA1)
{
    testSignCertificateNISTSECG(AsymmetricKey::NISTSECG_SECT571R1, MessageDigest::SHA1);
}

// Sign

// TEST_F(NistSecGEcTest, SignECKey_NISTSECG_SECP224R1_SHA1)
// {
//     testSignNISTSECGKey(AsymmetricKey::NISTSECG_SECP224R1, MessageDigest::SHA1);
// }

// TEST_F(NistSecGEcTest, SignECKey_NISTSECG_SECP384R1_SHA1)
// {
//     testSignNISTSECGKey(AsymmetricKey::NISTSECG_SECP384R1, MessageDigest::SHA1);
// }

// TEST_F(NistSecGEcTest, SignECKey_NISTSECG_SECP521R1_SHA1)
// {
//     testSignNISTSECGKey(AsymmetricKey::NISTSECG_SECP521R1, MessageDigest::SHA1);
// }

// TEST_F(NistSecGEcTest, SignECKey_NISTSECG_SECT163K1_SHA1)
// {
//     testSignNISTSECGKey(AsymmetricKey::NISTSECG_SECT163K1, MessageDigest::SHA1);
// }

// TEST_F(NistSecGEcTest, SignECKey_NISTSECG_SECT163R2_SHA1)
// {
//     testSignNISTSECGKey(AsymmetricKey::NISTSECG_SECT163R2, MessageDigest::SHA1);
// }

// TEST_F(NistSecGEcTest, SignECKey_NISTSECG_SECT233K1_SHA1)
// {
//     testSignNISTSECGKey(AsymmetricKey::NISTSECG_SECT233K1, MessageDigest::SHA1);
// }

// TEST_F(NistSecGEcTest, SignECKey_NISTSECG_SECT233R1_SHA1)
// {
//     testSignNISTSECGKey(AsymmetricKey::NISTSECG_SECT233R1, MessageDigest::SHA1);
// }

// TEST_F(NistSecGEcTest, SignECKey_NISTSECG_SECT283K1_SHA1)
// {
//     testSignNISTSECGKey(AsymmetricKey::NISTSECG_SECT283K1, MessageDigest::SHA1);
// }

// TEST_F(NistSecGEcTest, SignECKey_NISTSECG_SECT283R1_SHA1)
// {
//     testSignNISTSECGKey(AsymmetricKey::NISTSECG_SECT283R1, MessageDigest::SHA1);
// }

// TEST_F(NistSecGEcTest, SignECKey_NISTSECG_SECT409K1_SHA1)
// {
//     testSignNISTSECGKey(AsymmetricKey::NISTSECG_SECT409K1, MessageDigest::SHA1);
// }

// TEST_F(NistSecGEcTest, SignECKey_NISTSECG_SECT409R1_SHA1)
// {
//     testSignNISTSECGKey(AsymmetricKey::NISTSECG_SECT409R1, MessageDigest::SHA1);
// }

// TEST_F(NistSecGEcTest, SignECKey_NISTSECG_SECT571K1_SHA1)
// {
//     testSignNISTSECGKey(AsymmetricKey::NISTSECG_SECT571K1, MessageDigest::SHA1);
// }

// TEST_F(NistSecGEcTest, SignECKey_NISTSECG_SECT571R1_SHA1)
// {
//     testSignNISTSECGKey(AsymmetricKey::NISTSECG_SECT571R1, MessageDigest::SHA1);
// }

// Generate

TEST_F(NistSecGEcTest, GenerateECKeyPair_NISTSECG_SECP224R1)
{
    testGenerateNISTSECGKeyPair(AsymmetricKey::NISTSECG_SECP224R1);
}

TEST_F(NistSecGEcTest, GenerateECKeyPair_NISTSECG_SECP384R1)
{
    testGenerateNISTSECGKeyPair(AsymmetricKey::NISTSECG_SECP384R1);
}

TEST_F(NistSecGEcTest, GenerateECKeyPair_NISTSECG_SECP521R1)
{
    testGenerateNISTSECGKeyPair(AsymmetricKey::NISTSECG_SECP521R1);
}

TEST_F(NistSecGEcTest, GenerateECKeyPair_NISTSECG_SECT163K1)
{
    testGenerateNISTSECGKeyPair(AsymmetricKey::NISTSECG_SECT163K1);
}

TEST_F(NistSecGEcTest, GenerateECKeyPair_NISTSECG_SECT163R2)
{
    testGenerateNISTSECGKeyPair(AsymmetricKey::NISTSECG_SECT163R2);
}

TEST_F(NistSecGEcTest, GenerateECKeyPair_NISTSECG_SECT233K1)
{
    testGenerateNISTSECGKeyPair(AsymmetricKey::NISTSECG_SECT233K1);
}

TEST_F(NistSecGEcTest, GenerateECKeyPair_NISTSECG_SECT233R1)
{
    testGenerateNISTSECGKeyPair(AsymmetricKey::NISTSECG_SECT233R1);
}

TEST_F(NistSecGEcTest, GenerateECKeyPair_NISTSECG_SECT283K1)
{
    testGenerateNISTSECGKeyPair(AsymmetricKey::NISTSECG_SECT283K1);
}

TEST_F(NistSecGEcTest, GenerateECKeyPair_NISTSECG_SECT283R1)
{
    testGenerateNISTSECGKeyPair(AsymmetricKey::NISTSECG_SECT283R1);
}

TEST_F(NistSecGEcTest, GenerateECKeyPair_NISTSECG_SECT409K1)
{
    testGenerateNISTSECGKeyPair(AsymmetricKey::NISTSECG_SECT409K1);
}

TEST_F(NistSecGEcTest, GenerateECKeyPair_NISTSECG_SECT409R1)
{
    testGenerateNISTSECGKeyPair(AsymmetricKey::NISTSECG_SECT409R1);
}

TEST_F(NistSecGEcTest, GenerateECKeyPair_NISTSECG_SECT571K1)
{
    testGenerateNISTSECGKeyPair(AsymmetricKey::NISTSECG_SECT571K1);
}

TEST_F(NistSecGEcTest, GenerateECKeyPair_NISTSECG_SECT571R1)
{
    testGenerateNISTSECGKeyPair(AsymmetricKey::NISTSECG_SECT571R1);
}
