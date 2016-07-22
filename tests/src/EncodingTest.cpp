#include <libcryptosec/certificate/CertificateBuilder.h>
#include <fstream>
#include "gtest.h"
#include <iostream>
#include <sstream>

using std::endl;


class EncodingTest : public ::testing::Test {
protected:
    virtual void TearDown() {
        delete cbuilder;
        delete req;
    }

    /*!
     * @brief Inicializa os objetos utilizados nos testes.
     */
    void initialize() {
        req = new CertificateRequest(req_pem_encoded);
	    cbuilder = new CertificateBuilder(*req);

        rdn = RDNSequence(cbuilder->getSubject().getX509Name());
    }

    /*!
     * @brief Preenche as entradas de rdn.
     */
    void fillRDN() {
        RDNSequence tmp = RDNSequence();
        tmp.addEntry(RDNSequence::COUNTRY, "CO");
        tmp.addEntry(RDNSequence::STATE_OR_PROVINCE, "State");
        tmp.addEntry(RDNSequence::LOCALITY, "Locality");
        tmp.addEntry(RDNSequence::ORGANIZATION, "Organization");
        tmp.addEntry(RDNSequence::ORGANIZATION_UNIT, "Organization Unit");
        tmp.addEntry(RDNSequence::COMMON_NAME, "Commmon Name");
        rdn = tmp;
    }

    void modifyRDN() {
    	std::vector<std::pair<ObjectIdentifier, std::string> > entries = rdn.getEntries();
    	RDNSequence tmp;
    	tmp.addEntry(id2Type(entries[0].first.getNid()), "MD");    // precisa ter duas letras pois pode ser country name
    	for (unsigned int i = 1; i < entries.size(); i++) {
    		tmp.addEntry(id2Type(entries[i].first.getNid()), entries[i].second);
    	}
    	rdn = tmp;
    }

    /*!
     * @brief Testa se a codificacao das entradas estao de acordo com o esperado.
     */
    void testStringCodificaton(int expectedCodification) {
        X509_NAME* after = X509_get_subject_name(cbuilder->getX509());
        for (int i = 0; i < X509_NAME_entry_count(after); i++) {
            X509_NAME_ENTRY* entry = X509_NAME_get_entry(after, i);
            if (entry->object->nid != NID_countryName) {
            	int codification = entry->value->type;
            	ASSERT_EQ(codification, expectedCodification);
            }
        }
    }

    /*!
     * @brief Testa se os valores das entradas sao mantidos apos a geracao do certificado.
     */
    void testStringValues(RDNSequence r) {
        vector<pair<ObjectIdentifier, string> > entries_before = r.getEntries();
        vector<pair<ObjectIdentifier, string> > entries_after = rdn.getEntries();
        for (unsigned int i = 0; i < entries_before.size(); i++) {
            if (entries_before[i].first.getNid() == entries_after[i].first.getNid()) {
            	string before = entries_before[i].second;
            	string after = entries_after[i].second;
            	ASSERT_EQ(before, after);
            }
        }
    }

    /*!
     * @brief Testa se os RDNs estão na ordem padrão OpenSSL.
     */
    void testRDNOrder() {
    	vector<pair<ObjectIdentifier, std::string> > entries = rdn.getEntries();
    	int previous_type = id2Type(entries[0].first.getNid());
    	for (unsigned int i = 1; i < entries.size(); i++) {
    		int current_type = id2Type(entries[i].first.getNid());
    		ASSERT_GE(current_type, previous_type);
    		previous_type  = current_type;
    	}
    }

    /*!
     * @brief Define a requisica a ser testada como uma requisicao com o DN totalmente preenchido com codificacao
     *        V_ASN1_PRINTABLESTRING.
     */
    void setPEMFullPrintable() {
        using std::endl;
        std::stringstream stream;
        stream << "-----BEGIN CERTIFICATE REQUEST-----" << endl
               << "MIIDYTCCAkkCAQAwfDELMAkGA1UEBhMCUVExFjAUBgNVBAoTDW9yZyB5d3lyYSBB" << endl
               << "QzExGDAWBgNVBAsTD3Vub3JnIHl3eXJhIEFDMTEZMBcGA1UECBMQZXN0YWRvIHl3" << endl
               << "eXJhIEFDMTESMBAGA1UEAxMJeXd5cmEgQUMxMQwwCgYDVQQrEwNZV1kwggEiMA0G" << endl
               << "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjNaz7BMH/QOpAjf85A1gu2MAiHNiK" << endl
               << "Ne44BAwwWWz9tA3qyp543EF1ifj47zdL94rrP6+d/3YjaUNFPcaKf9cO+IFHv+OM" << endl
               << "X5DL8bw4dX7kf1HAjmx4c0+h7weR2hhpDiPiit13GP5xjunBHppnoW1iS8sw2Mcw" << endl
               << "m7iq6CqeNxGpsItJP2mvhPRxZvwDTo4X5BFyNwT33Z3eLZ6FBYWMUwvs44E2/Hwy" << endl
               << "nMaCUyxuuGUtQ3vmRfwGZK8qIMuZ0q9ekPvrtOW5rsOc+hKDy4C38zMr7moOKkba" << endl
               << "mHWLMKNKvT2+T7T82Hh0H/2IjtmQoDfZ+unmbCnmnicgqkmC6EV/23LtAgMBAAGg" << endl
               << "gZ8wgZwGCSqGSIb3DQEJDjGBjjCBizAdBgNVHQ4EFgQUAievAyNbAkadZzZRAyn/" << endl
               << "ZhvMFzcwKQYDVR0RBCIwIIIeY2FtcG8gcXVhbHF1ZXIgY29pc2EgeXd5cmEgQUMx" << endl
               << "MA8GA1UdEwEB/wQFMAMBAf8wDwYDVR0PAQH/BAUDAwcHgDAdBgNVHSUEFjAUBggr" << endl
               << "BgEFBQcDAQYIKwYBBQUHAwIwDQYJKoZIhvcNAQENBQADggEBAHGTUJZuOunsHq20" << endl
               << "JkCz6rB36GhUiosFHgTzQrTfuU+th1us3gQTm76ZFA85nDKqcn7R1+QOPWDxF/1n" << endl
               << "sgVljJqxPq23kd/P6dcKrsF7/bi/6DTbAQrIygHfIpjCRQWfbP/N7qg+cnZILXLI" << endl
               << "slJZW7HHztvG6QicahLJm9SZttLhm8gcDOKMNbrrolGSalMrPUg4qGI/jzrLZ68E" << endl
               << "nLTH+2ZKN8NdQpfTdgQ8BzcArYpXiYIe9VUUnFhFutWBh+cxcYXQuWRtbh+/AQiF" << endl
               << "fQndDsfisQnMHy/F7zaKtuoIH46AcM52NkDxn0FXEQaUBefgvywhBD0biQvPPJQU" << endl
               << "wfUDLbQ=" << endl
               << "-----END CERTIFICATE REQUEST-----";
        req_pem_encoded = stream.str();
    }

    /*!
     * @brief Converte um número representando um nid em um RDNSequence::EntryType.
     */
    RDNSequence::EntryType id2Type(int nid) {
    	switch (nid) {
    	case NID_countryName:            return RDNSequence::COUNTRY;
    	case NID_stateOrProvinceName:    return RDNSequence::STATE_OR_PROVINCE;
		case NID_localityName:           return RDNSequence::LOCALITY;
		case NID_organizationName:       return RDNSequence::ORGANIZATION;
		case NID_organizationalUnitName: return RDNSequence::ORGANIZATION_UNIT;
		case NID_commonName:             return RDNSequence::COMMON_NAME;
		default:                         return RDNSequence::UNKNOWN;
    	}
    }

    CertificateBuilder* cbuilder;  //!< CertificateBuilder usado para aplicar a funcao testada.
    CertificateRequest* req;  //!< CertificateRequest usado para aplicar a funcao testada.
    std::string req_pem_encoded;  //!< String usada para armazenar a requisicao PEM.
    RDNSequence rdn; //!< RDNSequence no qual a funcao deve ser aplicada.
};

/*!
 * @brief Testa se o certificado mantem a formatacao antes de ser emitido.
 */
TEST_F(EncodingTest, keepPrintable) {
    setPEMFullPrintable();
    initialize();
    cbuilder->alterSubject(rdn);
    testStringCodificaton(V_ASN1_PRINTABLESTRING);
}

/*!
 * @brief Testa se o certificado mantem a formatacao antes de ser emitido, com um campo adicionado durante a emissao.
 */
TEST_F(EncodingTest, keepPrintableAddedField) {
    setPEMFullPrintable();
    initialize();
    rdn.addEntry(RDNSequence::ORGANIZATION_UNIT, "OUnitName");
    cbuilder->alterSubject(rdn);
    testStringCodificaton(V_ASN1_PRINTABLESTRING);
}

TEST_F(EncodingTest, keepPrintableModifiedField) {
    setPEMFullPrintable();
    initialize();
    modifyRDN();
    cbuilder->alterSubject(rdn);
    testStringCodificaton(V_ASN1_PRINTABLESTRING);
}

/*!
 * @brief Testa se o certificado mantem a formatacao antes de ser emitido, com um campo adicionado durante a emissao.
 */
TEST_F(EncodingTest, keepStringValues) {
    setPEMFullPrintable();
    initialize();
    cbuilder->alterSubject(rdn);
    testStringValues(req->getSubject());
}

TEST_F(EncodingTest, keepStringModifiedField) {
    setPEMFullPrintable();
    initialize();
    modifyRDN();
    RDNSequence modified = rdn;
    cbuilder->alterSubject(rdn);
    testStringValues(modified);
}

