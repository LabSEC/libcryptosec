LIBS = -lp11 
INCLUDES = -I/home/labsec/openssl-1.0.0a/include/ -I./include
FLAGS = -shared
CC = g++
EXECUTABLES = libcryptosec.so

USER_OBJS += /home/labsec/openssl-1.0.0a/libcrypto.a

CPP_SRCS += \
./src/AsymmetricCipher.cpp \
./src/AsymmetricKey.cpp \
./src/Base64.cpp \
./src/BigInteger.cpp \
./src/ByteArray.cpp \
./src/DSAKeyPair.cpp \
./src/DSAPrivateKey.cpp \
./src/DSAPublicKey.cpp \
./src/ECDSAKeyPair.cpp \
./src/ECDSAPrivateKey.cpp \
./src/ECDSAPublicKey.cpp \
./src/DateTime.cpp \
./src/DynamicEngine.cpp \
./src/Engine.cpp \
./src/Engines.cpp \
./src/KeyPair.cpp \
./src/MessageDigest.cpp \
./src/NetscapeSPKI.cpp \
./src/NetscapeSPKIBuilder.cpp \
./src/OpenSSLErrorHandler.cpp \
./src/Pkcs7.cpp \
./src/Pkcs7Builder.cpp \
./src/Pkcs7CertificateBundle.cpp \
./src/Pkcs7CertificateBundleBuilder.cpp \
./src/Pkcs7EnvelopedData.cpp \
./src/Pkcs7EnvelopedDataBuilder.cpp \
./src/Pkcs7Factory.cpp \
./src/Pkcs7SignedData.cpp \
./src/Pkcs7SignedDataBuilder.cpp \
./src/Pkcs12.cpp \
./src/Pkcs12Factory.cpp \
./src/Pkcs12Builder.cpp \
./src/PrivateKey.cpp \
./src/PublicKey.cpp \
./src/RSAKeyPair.cpp \
./src/RSAPrivateKey.cpp \
./src/RSAPublicKey.cpp \
./src/Random.cpp \
./src/SecretSharer.cpp \
./src/Signer.cpp \
./src/SmartcardCertificate.cpp \
./src/SmartcardReader.cpp \
./src/SmartcardSlot.cpp \
./src/SmartcardSlots.cpp \
./src/SymmetricCipher.cpp \
./src/SymmetricKey.cpp \
./src/SymmetricKeyGenerator.cpp \
./src/certificate/AuthorityKeyIdentifierExtension.cpp \
./src/certificate/BasicConstraintsExtension.cpp \
./src/certificate/CRLDistributionPointsExtension.cpp \
./src/certificate/AuthorityInformationAccessExtension.cpp \
./src/certificate/Certificate.cpp \
./src/certificate/CertificateBuilder.cpp \
./src/certificate/CertificatePoliciesExtension.cpp \
./src/certificate/CertificateRequest.cpp \
./src/certificate/CertificateRequestSPKAC.cpp \
./src/certificate/CertificateRequestFactory.cpp \
./src/certificate/CertificateRevocationList.cpp \
./src/certificate/CertificateRevocationListBuilder.cpp \
./src/certificate/DistributionPoint.cpp \
./src/certificate/AccessDescription.cpp \
./src/certificate/DistributionPointName.cpp \
./src/certificate/ExtendedKeyUsageExtension.cpp \
./src/certificate/Extension.cpp \
./src/certificate/GeneralName.cpp \
./src/certificate/GeneralNames.cpp \
./src/certificate/IssuerAlternativeNameExtension.cpp \
./src/certificate/KeyUsageExtension.cpp \
./src/certificate/ObjectIdentifier.cpp \
./src/certificate/ObjectIdentifierFactory.cpp \
./src/certificate/PolicyInformation.cpp \
./src/certificate/PolicyQualifierInfo.cpp \
./src/certificate/RDNSequence.cpp \
./src/certificate/RevokedCertificate.cpp \
./src/certificate/SubjectAlternativeNameExtension.cpp \
./src/certificate/SubjectInformationAccessExtension.cpp \
./src/certificate/SubjectKeyIdentifierExtension.cpp \
./src/certificate/UserNotice.cpp \
./src/certificate/CRLNumberExtension.cpp \
 
OBJS += \
./src/AsymmetricCipher.o \
./src/AsymmetricKey.o \
./src/Base64.o \
./src/BigInteger.o \
./src/ByteArray.o \
./src/DSAKeyPair.o \
./src/DSAPrivateKey.o \
./src/DSAPublicKey.o \
./src/ECDSAKeyPair.o \
./src/ECDSAPrivateKey.o \
./src/ECDSAPublicKey.o \
./src/DateTime.o \
./src/DynamicEngine.o \
./src/Engine.o \
./src/Engines.o \
./src/KeyPair.o \
./src/MessageDigest.o \
./src/NetscapeSPKI.o \
./src/NetscapeSPKIBuilder.o \
./src/OpenSSLErrorHandler.o \
./src/Pkcs7.o \
./src/Pkcs7Builder.o \
./src/Pkcs7CertificateBundle.o \
./src/Pkcs7CertificateBundleBuilder.o \
./src/Pkcs7EnvelopedData.o \
./src/Pkcs7EnvelopedDataBuilder.o \
./src/Pkcs7Factory.o \
./src/Pkcs7SignedData.o \
./src/Pkcs7SignedDataBuilder.o \
./src/Pkcs12.o \
./src/Pkcs12Factory.o \
./src/Pkcs12Builder.o \
./src/PrivateKey.o \
./src/PublicKey.o \
./src/RSAKeyPair.o \
./src/RSAPrivateKey.o \
./src/RSAPublicKey.o \
./src/Random.o \
./src/SecretSharer.o \
./src/Signer.o \
./src/SmartcardCertificate.o \
./src/SmartcardReader.o \
./src/SmartcardSlot.o \
./src/SmartcardSlots.o \
./src/SymmetricCipher.o \
./src/SymmetricKey.o \
./src/SymmetricKeyGenerator.o \
./src/certificate/AuthorityKeyIdentifierExtension.o \
./src/certificate/BasicConstraintsExtension.o \
./src/certificate/CRLDistributionPointsExtension.o \
./src/certificate/AuthorityInformationAccessExtension.o \
./src/certificate/Certificate.o \
./src/certificate/CertificateBuilder.o \
./src/certificate/CertificatePoliciesExtension.o \
./src/certificate/CertificateRequest.o \
./src/certificate/CertificateRequestSPKAC.o \
./src/certificate/CertificateRequestFactory.o \
./src/certificate/CertificateRevocationList.o \
./src/certificate/CertificateRevocationListBuilder.o \
./src/certificate/DistributionPoint.o \
./src/certificate/AccessDescription.o \
./src/certificate/DistributionPointName.o \
./src/certificate/ExtendedKeyUsageExtension.o \
./src/certificate/Extension.o \
./src/certificate/GeneralName.o \
./src/certificate/GeneralNames.o \
./src/certificate/IssuerAlternativeNameExtension.o \
./src/certificate/KeyUsageExtension.o \
./src/certificate/ObjectIdentifier.o \
./src/certificate/ObjectIdentifierFactory.o \
./src/certificate/PolicyInformation.o \
./src/certificate/PolicyQualifierInfo.o \
./src/certificate/RDNSequence.o \
./src/certificate/RevokedCertificate.o \
./src/certificate/SubjectAlternativeNameExtension.o \
./src/certificate/SubjectInformationAccessExtension.o \
./src/certificate/SubjectKeyIdentifierExtension.o \
./src/certificate/UserNotice.o \
./src/certificate/CRLNumberExtension.o \

CPP_DEPS += \
./src/AsymmetricCipher.d \
./src/AsymmetricKey.d \
./src/Base64.d \
./src/BigInteger.d \
./src/ByteArray.d \
./src/DSAKeyPair.d \
./src/DSAPrivateKey.d \
./src/DSAPublicKey.d \
./src/ECDSAKeyPair.d \
./src/ECDSAPrivateKey.d \
./src/ECDSAPublicKey.d \
./src/DateTime.d \
./src/DynamicEngine.d \
./src/Engine.d \
./src/Engines.d \
./src/KeyPair.d \
./src/MessageDigest.d \
./src/NetscapeSPKI.d \
./src/NetscapeSPKIBuilder.d \
./src/OpenSSLErrorHandler.d \
./src/Pkcs7.d \
./src/Pkcs7Builder.d \
./src/Pkcs7CertificateBundle.d \
./src/Pkcs7CertificateBundleBuilder.d \
./src/Pkcs7EnvelopedData.d \
./src/Pkcs7EnvelopedDataBuilder.d \
./src/Pkcs7Factory.d \
./src/Pkcs7SignedData.d \
./src/Pkcs7SignedDataBuilder.d \
./src/Pkcs12.d \
./src/Pkcs12Factory.d \
./src/Pkcs12Builder.d \
./src/PrivateKey.d \
./src/PublicKey.d \
./src/RSAKeyPair.d \
./src/RSAPrivateKey.d \
./src/RSAPublicKey.d \
./src/Random.d \
./src/SecretSharer.d \
./src/Signer.d \
./src/SmartcardCertificate.d \
./src/SmartcardReader.d \
./src/SmartcardSlot.d \
./src/SmartcardSlots.d \
./src/SymmetricCipher.d \
./src/SymmetricKey.d \
./src/SymmetricKeyGenerator.d \
./src/certificate/AuthorityKeyIdentifierExtension.d \
./src/certificate/BasicConstraintsExtension.d \
./src/certificate/CRLDistributionPointsExtension.d \
./src/certificate/AuthorityInformationAccessExtension.d \
./src/certificate/Certificate.d \
./src/certificate/CertificateBuilder.d \
./src/certificate/CertificatePoliciesExtension.d \
./src/certificate/CertificateRequest.d \
./src/certificate/CertificateRequestSPKAC.d \
./src/certificate/CertificateRequestFactory.d \
./src/certificate/CertificateRevocationList.d \
./src/certificate/CertificateRevocationListBuilder.d \
./src/certificate/DistributionPoint.d \
./src/certificate/AccessDescription.d \
./src/certificate/DistributionPointName.d \
./src/certificate/ExtendedKeyUsageExtension.d \
./src/certificate/Extension.d \
./src/certificate/GeneralName.d \
./src/certificate/GeneralNames.d \
./src/certificate/IssuerAlternativeNameExtension.d \
./src/certificate/KeyUsageExtension.d \
./src/certificate/ObjectIdentifier.d \
./src/certificate/ObjectIdentifierFactory.d \
./src/certificate/PolicyInformation.d \
./src/certificate/PolicyQualifierInfo.d \
./src/certificate/RDNSequence.d \
./src/certificate/RevokedCertificate.d \
./src/certificate/SubjectAlternativeNameExtension.d \
./src/certificate/SubjectInformationAccessExtension.d \
./src/certificate/SubjectKeyIdentifierExtension.d \
./src/certificate/UserNotice.d \
./src/certificate/CRLNumberExtension.d \

src/%.o: ./src/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ $(INCLUDES) -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

$(EXECUTABLES):	$(OBJS)
	$(CC) $(FLAGS) -o $(EXECUTABLES) $(OBJS) $(USER_OBJS) $(LIBS)  
	@echo 'Build complete!'

clean:
	rm -rf $(CPP_DEPS) $(OBJS) $(EXECUTABLES)
	
install: $(EXECUTABLES)
	@echo 'Installing libcryptosec ...'
	@mkdir -p $(DESTDIR)/usr/lib
	@cp libcryptosec.so $(DESTDIR)/usr/lib
	@mkdir -m 0755 -p $(DESTDIR)/usr/include/libcryptosec
	@mkdir -m 0755 -p $(DESTDIR)/usr/include/libcryptosec/exception
	@mkdir -m 0755 -p $(DESTDIR)/usr/include/libcryptosec/certificate
	@cp -f include/libcryptosec/*.h $(DESTDIR)/usr/include/libcryptosec/
	@cp -f include/libcryptosec/exception/* $(DESTDIR)/usr/include/libcryptosec/exception
	@cp -f include/libcryptosec/certificate/* $(DESTDIR)/usr/include/libcryptosec/certificate
	@echo 'Instalation complete!'

uninstall:
	@echo 'Uninstalling libcryptosec ...'
	@rm -rf $(DESTDIR)/usr/lib/$(EXECUTABLES)
	@rm -rf $(DESTDIR)/usr/include/libcryptosec
	@echo 'Uninstalation complete!'

