cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

add_subdirectory(asn1)
add_subdirectory(certificate)
add_subdirectory(ec)

set(SOURCE_FILES
        AsymmetricCipher.cpp
        AsymmetricKey.cpp
        Base64.cpp
        BigInteger.cpp
        ByteArray.cpp
        DateTime.cpp
        DSAKeyPair.cpp
        DSAPrivateKey.cpp
        DSAPublicKey.cpp
        DynamicEngine.cpp
        ECDSAKeyPair.cpp
        ECDSAPrivateKey.cpp
        ECDSAPublicKey.cpp
        Engine.cpp
        Engines.cpp
        Hmac.cpp
        KeyPair.cpp
        MessageDigest.cpp
        NetscapeSPKI.cpp
        NetscapeSPKIBuilder.cpp
        OpenSSLErrorHandler.cpp
        Pkcs12.cpp
        Pkcs12Builder.cpp
        Pkcs12Factory.cpp
        Pkcs7.cpp
        Pkcs7Builder.cpp
        Pkcs7CertificateBundle.cpp
        Pkcs7CertificateBundleBuilder.cpp
        Pkcs7EnvelopedData.cpp
        Pkcs7EnvelopedDataBuilder.cpp
        Pkcs7Factory.cpp
        Pkcs7SignedData.cpp
        Pkcs7SignedDataBuilder.cpp
        PrivateKey.cpp
        PublicKey.cpp
        Random.cpp
        RSAKeyPair.cpp
        RSAPrivateKey.cpp
        RSAPublicKey.cpp
        SecretSharer.cpp
        Signer.cpp
        SignerInformation.cpp
        SmartcardCertificate.cpp
        SmartcardReader.cpp
        SmartcardSlot.cpp
        SmartcardSlots.cpp
        SymmetricCipher.cpp
        SymmetricKey.cpp
        SymmetricKeyGenerator.cpp)

add_library(cryptosec STATIC ${SOURCE_FILES})
target_link_libraries(cryptosec asn1 certificate ec ${OPENSSL_LIBRARIES} ${LIBP11_LIBRARIES})

install(TARGETS cryptosec
        DESTINATION lib)
