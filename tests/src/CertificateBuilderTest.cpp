#include <libcryptosec/certificate/CertificateBuilder.h>
#include <fstream>
#include <iostream>
#include "gtest.h"

class CertificateBuilderTest : public ::testing::Test {

protected:
	virtual void SetUp() {
	}

    virtual void TearDown() {
    }

    RDNSequence buildRDNSubject(std::string country, std::string organization,
    		std::string oUnit, std::string common_name) {
    	RDNSequence rdnSubject;
		rdnSubject.addEntry(RDNSequence::COUNTRY, country);
		rdnSubject.addEntry(RDNSequence::ORGANIZATION, organization);
		rdnSubject.addEntry(RDNSequence::ORGANIZATION_UNIT, oUnit);
		rdnSubject.addEntry(RDNSequence::COMMON_NAME, common_name);

		return rdnSubject;
    }

    CertificateBuilder* certBuilder;  //!< CertificateBuilder usado para aplicar a funcao testada.
    CertificateRequest* certReq;  //!< CertificateRequest usado para aplicar a funcao testada.

};

TEST_F(CertificateBuilderTest, AlterSubject_EmptyCommonName) {
	std::string pem = "-----BEGIN CERTIFICATE REQUEST-----" "\n"
			"MIIC9DCCAdwCAQAwga4xCzAJBgNVBAYTAkJSMRMwEQYDVQQIDApTb21lLVN0YXRl" "\n"
			"MRMwEQYDVQQKDApJQ1AtQnJhc2lsMTQwMgYDVQQLDCtBdXRvcmlkYWRlIENlcnRp" "\n"
			"ZmljYWRvcmEgUmFpeiBCcmFzaWxlaXJhIHYyMT8wPQYDVQQDDDZBdXRvcmlkYWRl" "\n"
			"IENlcnRpZmljYWRvcmEgZGEgQ2FzYSBkYSBNb2VkYSBkbyBCcmFzaWwgdjMwggEi" "\n"
			"MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/uaaTgYwZn7ljN+gZ8CaLQxaE" "\n"
			"F/cUuidC48ms6QHTzRLhyQlTadBW/0hnVFHZ5yEXCNAmlOTLkFVroyeu6E8LK5Gx" "\n"
			"R0rFP6kuhofjvEiJiUCGZdk2wjVl8S8FqqlO6kYriYqi2Mv0O3NRJ2PP+dLNO4ja" "\n"
			"Xu/SzkpKBXuPwoOpTvmwOr/vyiivDfZE3TteMC1YmVO2vW5gP1jHQECKOSWbvZUo" "\n"
			"SEXmkLr6+EzgmUFcabf2mhKyxaSAPKbAx3U5zNMwR0Sq+Vdgiv2nVCRQ/hiaZ9cc" "\n"
			"YFBUCs9yqs4ffpzasZbwsdnxdRd6sNRpMlWS7hGfEuSWQxNGLGcwXWRWk4vhAgMB" "\n"
			"AAGgADANBgkqhkiG9w0BAQUFAAOCAQEAPKWxdsutgYT7PXiCqWf8y31JK6Jl1Ify" "\n"
			"iG6FeRTODLn+rv7Ehu3qpcZKbMUMfYrjWAi9i34TF5nkJTo26xlF0VzwO7MAsy51" "\n"
			"cOXvEmMqVf9BUYjJ9Ig+JEAD7ucz0/zovX9wBwU+EhYwRvfRbXSf4INsoTmW6LBw" "\n"
			"OXkmGSQANvvYr7gWDgbaW5D7p3mxLoN4YBdu8MBWFVJ3h3+BNowyqD2t+ye977zi" "\n"
			"xFKAjfXIijHVfoOUwC/QRO57CBzB1TNTNxNPa+j2SYQKrImGX4nLkJE2WA8vwY37" "\n"
			"+eX2YIRBXRS8KrwGWNo0CTiN1PDL2iceXJExrxKVjA51o9j9tVAnPw==" "\n"
			"-----END CERTIFICATE REQUEST-----";
	CertificateRequest certReq(pem);
	CertificateBuilder *certBuilder = new CertificateBuilder(certReq);

	RDNSequence rdnAlterSubject = buildRDNSubject("BR", "ICP-Brasil", "Autoridade Certificadora Raiz Brasileira v2",
			"" /*Autoridade Certificadora da Casa da Moeda do Brasil v3*/);

	certBuilder->alterSubject(rdnAlterSubject);
	RDNSequence rdnNewSubject = certBuilder->getSubject();

	std::string country = rdnNewSubject.getEntries(RDNSequence::COUNTRY).back();
	std::string organization = rdnNewSubject.getEntries(RDNSequence::ORGANIZATION).at(0);
	std::string oUnit = rdnNewSubject.getEntries(RDNSequence::ORGANIZATION_UNIT).at(0);

	EXPECT_STREQ(country.c_str(), "BR");
	EXPECT_STREQ(organization.c_str(), "ICP-Brasil");
	EXPECT_STREQ(oUnit.c_str(), "Autoridade Certificadora Raiz Brasileira v2");
	EXPECT_EQ(0, (int) rdnNewSubject.getEntries(RDNSequence::COMMON_NAME).size());

	delete certBuilder;
}
