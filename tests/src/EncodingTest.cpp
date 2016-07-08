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
    void fillRDN() {  // TODO: Falta UserId
        RDNSequence tmp = RDNSequence();
        tmp.addEntry(RDNSequence::COUNTRY, "CO");
        tmp.addEntry(RDNSequence::STATE_OR_PROVINCE, "State");
        tmp.addEntry(RDNSequence::LOCALITY, "Locality");
        tmp.addEntry(RDNSequence::ORGANIZATION, "Organization");
        tmp.addEntry(RDNSequence::ORGANIZATION_UNIT, "Organization Unit");
        tmp.addEntry(RDNSequence::COMMON_NAME, "Commmon Name");
        rdn = tmp;
    }

    /*!
     * @brief Testa se a codificacao das entradas estao de acordo com o esperado.
     */
    bool testStringCodificaton(int expectedCodification) {
        X509_NAME* after = X509_get_subject_name(cbuilder->getX509());
        for (int i = 0; i < X509_NAME_entry_count(after); i++) {
            X509_NAME_ENTRY* entry = X509_NAME_get_entry(after, i);
            if (entry->object->nid != NID_countryName && entry->value->type != expectedCodification) {
                return false;
            }
        }
        return true;
    }

    /*!
     * @brief Testa se os valores das entradas sao mantidos apos a geracao do certificado.
     */
    bool testStringValues() {
        std::vector<std::pair<ObjectIdentifier, std::string> > entries_before = req->getSubject().getEntries();
        std::vector<std::pair<ObjectIdentifier, std::string> > entries_after = rdn.getEntries();
        for (int i = 0; i < (int) entries_before.size(); i++) {
            if (entries_before[i].first.getNid() == entries_after[i].first.getNid() &&
                entries_before[i].second != entries_after[i].second) {
                return false;
            }
        }
        return true;
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
    ASSERT_TRUE(testStringCodificaton(V_ASN1_PRINTABLESTRING));
}

/*!
 * @brief Testa se o certificado mantem a formatacao antes de ser emitido, com um campo adicionado durante a emissao.
 */
TEST_F(EncodingTest, keepPrintableAddedField) {
    setPEMFullPrintable();
    initialize();
    cbuilder->alterSubject(rdn);
    rdn.addEntry(RDNSequence::ORGANIZATION_UNIT, "OUnitName");
    ASSERT_TRUE(testStringCodificaton(V_ASN1_PRINTABLESTRING));
}

/*!
 * @brief Testa se o certificado mantem a formatacao antes de ser emitido, com um campo adicionado durante a emissao.
 */
TEST_F(EncodingTest, keepStringValues) {
    setPEMFullPrintable();
    initialize();
    cbuilder->alterSubject(rdn);
    ASSERT_TRUE(testStringValues());
}
