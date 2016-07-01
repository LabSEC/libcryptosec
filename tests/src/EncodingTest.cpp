#include <libcryptosec/certificate/CertificateBuilder.h>
#include <fstream>
#include "gtest.h"
#include <iostream>
#include <sstream>

using std::endl;


class EncodingTest : public ::testing::Test {
protected:
    virtual void SetUp() {
        cbuilder = new CertificateBuilder();
        req = CertificateRequest();
        before = X509_NAME_new();
        after = X509_NAME_new();

        initialization();
    }

    virtual void TearDown() {
        delete cbuilder;
        X509_NAME_free(before);
        X509_NAME_free(after);
    }

    void initialization() {
        entry_fields.insert(std::make_pair<int, const char*>(NID_countryName, LN_countryName));
        entry_fields.insert(std::make_pair<int, const char*>(NID_stateOrProvinceName, LN_stateOrProvinceName));
        entry_fields.insert(std::make_pair<int, const char*>(NID_localityName, LN_localityName));
        entry_fields.insert(std::make_pair<int, const char*>(NID_organizationName, LN_organizationName));
        entry_fields.insert(std::make_pair<int, const char*>(NID_organizationalUnitName, LN_organizationalUnitName));
        entry_fields.insert(std::make_pair<int, const char*>(NID_commonName, LN_commonName));
        entry_fields.insert(std::make_pair<int, const char*>(NID_userId, LN_userId));
        std::stringstream stream;
        stream << 	"some pem encoded";
        req_pem_encoded = stream.str();
        req = CertificateRequest(req_pem_encoded);
//		cbuilder = new CertificateBuilder(req);
    }

    /*!
     * @brief Adiciona uma entrada de um X509_NAME com a codificaÃ§Ã£o desejada.
     *
     * @param name Ponteiro para o X509_NAME.
     * @param entry Entrada a ser adicionada.
     * @param encoding CodificaÃ§Ã£o desejada.
     */
    void addNameEntry(X509_NAME* name, const char* entry, int encoding, int NID) {
        X509_NAME_ENTRY *new_entry = X509_NAME_ENTRY_new();
        if (NID == NID_countryName) {
            X509_NAME_ENTRY_create_by_NID(&new_entry, NID, V_ASN1_PRINTABLESTRING, (unsigned char*)entry, strlen(entry));
            X509_NAME_add_entry(name, new_entry, -1, 0);
        }
        else {
            X509_NAME_ENTRY_create_by_NID(&new_entry, NID, encoding, (unsigned char*)entry, strlen(entry));
            X509_NAME_add_entry(name, new_entry, -1, 0);
        }
        X509_NAME_ENTRY_free(new_entry);
    }

    /*!
     * @brief Adiciona as entradas DN de um X509_NAME com a codificaÃ§Ã£o desejada.
     *
     * @param name Ponteiro para o X509_NAME.
     * @param encoding CodificaÃ§Ã£o desejada.
     */
    void fillEntries(X509_NAME* name, int encoding) {
        for(std::map<int, const char*>::iterator entries = entry_fields.begin(); entries != entry_fields.end(); entries++){
            addNameEntry(name, entries->second, encoding, entries->first);
            rdn.addEntry(id2Type(entries->first), entries->second);
        }
    }

    /*!
     * @brief Aplica um caso de teste com todas as entradas preenchidas com a codificaÃ§Ã£o desejada.
     *
     * @param encoding CodificaÃ§Ã£o desejada.
     *
     * @return true se o caso de teste estiver correto, falso caso contrÃ¡rio.
     */
    void populateCertificateBuilderX509(int entriesCodification) {
        // create requisition and populate certificateBuilder:
        fillEntries(before, entriesCodification);
        X509_set_subject_name(cbuilder->getX509(), X509_NAME_dup(before));
    }

    void populateCertificateBuilderPem(int entriesCodification) {
        // create requisition and populate certificateBuilder:
        cbuilder = new CertificateBuilder(req);
        fillEntries(before, entriesCodification);
    }

    /*!
     * @brief Aplica um caso de teste com uma entrada preenchida com a codificaÃ§Ã£o desejada e as restantes com a
     *        codificaÃ§Ã£o padrÃ£o da versÃ£o OpenSSL.
     *
     * @param entry Entrada
     * @param encoding CodificaÃ§Ã£o desejada.
     *
     * @return true se o caso de teste estiver correto, falso caso contrÃ¡rio.
     */
    void applyOne(const char* entry, int encoding) {
        // create certificate:
        addNameEntry(before, entry, encoding, NID_commonName);    // insere a entrada se nÃ£o for common name
        X509_set_subject_name(cbuilder->getX509(), X509_NAME_dup(before));

        // fill entries and apply alterSubject:
        fillEntries(before, MBSTRING_ASC);
        RDNSequence rrr(X509_NAME_dup(before));
        cbuilder->alterSubject(rrr);
        after = X509_NAME_dup(X509_get_subject_name(cbuilder->getX509()));
    }

    void alterRDNSequences() {
        // apply alterSubject:
        cbuilder->alterSubject(rdn);
        after = X509_NAME_dup(X509_get_subject_name(cbuilder->getX509()));
    }

    /*!
     * @brief Testa se a codificaÃ§Ã£o das entradas estÃ£o de acordo com o esperado.
     *
     * Testa se a codificaÃ§Ã£o das entradas no certificado gerado estÃ£o de acordo com a primeira entrada commonName que Ã©
     * obrigatÃ³ria na geraÃ§Ã£o da requisiÃ§Ã£o.
     */
    bool testStringCodificaton(int expectedCodification) {
        for (int i = 0; i < X509_NAME_entry_count(after); i++) {
            X509_NAME_ENTRY* entry = X509_NAME_get_entry(after, i);
            if (entry->object->nid != NID_countryName) {
                if(entry->value->type != expectedCodification) {
                    return false;
                }
            }
        }
        return true;
    }

    bool testStringValues() {
        return true;
    }

    int getReqStringCodification() {
        return 0;
    }

    int getCertStringCodification() {
        return 0;
    }

    RDNSequence::EntryType id2Type(int id) {
        RDNSequence::EntryType ret;
        switch (id) {
            case NID_countryName: ret = RDNSequence::COUNTRY; break;
            case NID_organizationName: ret = RDNSequence::ORGANIZATION; break;
            case NID_organizationalUnitName: ret = RDNSequence::ORGANIZATION_UNIT; break;
            case NID_dnQualifier: ret = RDNSequence::DN_QUALIFIER; break;
            case NID_stateOrProvinceName: ret = RDNSequence::STATE_OR_PROVINCE; break;
            case NID_commonName: ret = RDNSequence::COMMON_NAME; break;
            case NID_serialNumber: ret = RDNSequence::SERIAL_NUMBER; break;
            case NID_localityName: ret = RDNSequence::LOCALITY; break;
            case NID_title: ret = RDNSequence::TITLE; break;
            case NID_surname: ret = RDNSequence::SURNAME; break;
            case NID_givenName: ret = RDNSequence::GIVEN_NAME; break;
            case NID_initials: ret = RDNSequence::INITIALS; break;
            case NID_pseudonym: ret = RDNSequence::PSEUDONYM; break;
            case NID_generationQualifier: ret = RDNSequence::GENERATION_QUALIFIER; break;
            case NID_pkcs9_emailAddress: ret = RDNSequence::EMAIL; break;
            case NID_domainComponent: ret = RDNSequence::DOMAIN_COMPONENT; break;
            default: ret = RDNSequence::UNKNOWN;
        }
        return ret;
    }

    CertificateBuilder* cbuilder;  //!< CertificateBuilder usado para aplicar a funÃ§Ã£o testada.
    std::string req_pem_encoded;
    CertificateRequest req;
    RDNSequence rdn;
    X509_NAME* before;  //!< Ponteiro para o X509_NAME antes de aplicar a funÃ§Ã£o testada.
    X509_NAME* after;  //!< Ponteiro para o X509_NAME depois de aplicar a funÃ§Ã£o testada.


    std::map<int, const char*> entry_fields;
};

/**
 * AtravÃ©s de uma requisiÃ§Ã£o previamente gerada, testa se o certificado mantem a formataÃ§Ã£o antes de ser emitido.
 *
 **/
 TEST_F(EncodingTest, ReqPEM_keep_codification) {
	 populateCertificateBuilderPem(V_ASN1_UTF8STRING);

     ASSERT_TRUE(testStringCodificaton(V_ASN1_UTF8STRING));
 }

/**
 * Tests se a codificaÃ§Ã£o do re
 */

 TEST_F(EncodingTest, ReqPEM_alter_all_fields) {
	 populateCertificateBuilderPem(V_ASN1_UTF8STRING);
	 alterRDNSequences();

     ASSERT_TRUE(testStringCodificaton(V_ASN1_PRINTABLESTRING));
 }




/*!
 * @brief Teste usando todas as entradas preenchidas com codificaÃ§Ã£o V_ASN1_PRINTABLESTRING.
 *
 * Simula a situaÃ§Ã£o onde os campos sÃ£o preenchidos na geraÃ§Ã£o da requisiÃ§Ã£o, devendo manter sua codificaÃ§Ã£o no
 * certificado gerado.
 */
//TEST_F(EncodingTest, PrintableFilled) {
//    ASSERT_TRUE(createCertificate(V_ASN1_PRINTABLESTRING));
//}
//
///*!
// * @brief Teste usando as entradas commonName e countryName preenchidas com codificaÃ§Ã£o V_ASN1_PRINTABLESTRING e as
// *        restantes com codificaÃ§Ã£o MBSTRING_ASC.
// *
// * Simula a situaÃ§Ã£o onde os campos Common Name e Country Name sÃ£o preenchidos na geraÃ§Ã£o da requisiÃ§Ã£o e os restantes
// * sÃ£o adicionados na geraÃ§Ã£o do certificado, devendo usar a codificaÃ§Ã£o dos campos jÃ¡ exsitentes na requisiÃ§Ã£o.
// */
//TEST_F(EncodingTest, PrintablecountryName) {
//    ASSERT_TRUE(applyOne(LN_countryName, V_ASN1_PRINTABLESTRING));
//}
//
///*!
// * @brief Teste usando as entradas commonName e stateOrProvinceName preenchidas com codificaÃ§Ã£o V_ASN1_PRINTABLESTRING e
// *        as restantes com codificaÃ§Ã£o MBSTRING_ASC.
// *
// * Simula a situaÃ§Ã£o onde os campos Common Name e State or Province Name sÃ£o preenchidos na geraÃ§Ã£o da requisiÃ§Ã£o e os
// * restantes sÃ£o adicionados na geraÃ§Ã£o do certificado, devendo usar a codificaÃ§Ã£o dos campos jÃ¡ exsitentes na
// * requisiÃ§Ã£o.
// */
//TEST_F(EncodingTest, PrintableState) {
//    ASSERT_TRUE(applyOne(LN_stateOrProvinceName, V_ASN1_PRINTABLESTRING));
//}
//
///*!
// * @brief Teste usando as entradas commonName e localityName preenchidas com codificaÃ§Ã£o V_ASN1_PRINTABLESTRING e as
// *        restantes com codificaÃ§Ã£o MBSTRING_ASC.
// *
// * Simula a situaÃ§Ã£o onde os campos Common Name e Locality Name sÃ£o preenchidos na geraÃ§Ã£o da requisiÃ§Ã£o e os restantes
// * sÃ£o adicionados na geraÃ§Ã£o do certificado, devendo usar a codificaÃ§Ã£o dos campos jÃ¡ exsitentes na requisiÃ§Ã£o.
// */
//TEST_F(EncodingTest, PrintableLocality) {
//    ASSERT_TRUE(applyOne(LN_localityName, V_ASN1_PRINTABLESTRING));
//}
//
///*!
// * @brief Teste usando as entradas commonName e organizationName preenchidas com codificaÃ§Ã£o V_ASN1_PRINTABLESTRING e as
// *        restantes com codificaÃ§Ã£o MBSTRING_ASC.
// *
// * Simula a situaÃ§Ã£o onde os campos Common Name e Organization Name sÃ£o preenchidos na geraÃ§Ã£o da requisiÃ§Ã£o e os
// * restantes sÃ£o adicionados na geraÃ§Ã£o do certificado, devendo usar a codificaÃ§Ã£o dos campos jÃ¡ exsitentes na
// * requisiÃ§Ã£o.
// */
//TEST_F(EncodingTest, PrintableOrganization) {
//    ASSERT_TRUE(applyOne(LN_organizationName, V_ASN1_PRINTABLESTRING));
//}
//
///*!
// * @brief Teste usando as entradas commonName e organizationalUnitName preenchidas com codificaÃ§Ã£o
// *        V_ASN1_PRINTABLESTRING e as restantes com codificaÃ§Ã£o MBSTRING_ASC.
// *
// * Simula a situaÃ§Ã£o onde os campos Common Name e Organizational Unit Name sÃ£o preenchidos na geraÃ§Ã£o da requisiÃ§Ã£o e os
// * restantes sÃ£o adicionados na geraÃ§Ã£o do certificado, devendo usar a codificaÃ§Ã£o dos campos jÃ¡ exsitentes na
// * requisiÃ§Ã£o.
// */
//TEST_F(EncodingTest, PrintableOrganizationalUnit) {
//    ASSERT_TRUE(applyOne(LN_organizationalUnitName, V_ASN1_PRINTABLESTRING));
//}
//
///*!
// * @brief Teste usando a entrada commonName preenchida com codificaÃ§Ã£o V_ASN1_PRINTABLESTRING e asrestantes com
// *        codificaÃ§Ã£o MBSTRING_ASC.
// *
// * Simula a situaÃ§Ã£o onde apenas o campo Common Name Ã© preenchido na geraÃ§Ã£o da requisiÃ§Ã£o e os restantes sÃ£o
// * adicionados na geraÃ§Ã£o do certificado, devendo usar a codificaÃ§Ã£o dos campos jÃ¡ exsitentes na requisiÃ§Ã£o.
// */
//TEST_F(EncodingTest, PrintableCommonName) {
//    ASSERT_TRUE(applyOne(LN_commonName, V_ASN1_PRINTABLESTRING));
//}
//
///*!
// * @brief Teste usando as entradas commonName e userId preenchidas com codificaÃ§Ã£o V_ASN1_PRINTABLESTRING e as
// *        restantes com codificaÃ§Ã£o MBSTRING_ASC.
// *
// * Simula a situaÃ§Ã£o onde os campos Common Name e User ID sÃ£o preenchidos na geraÃ§Ã£o da requisiÃ§Ã£o e os restantes sÃ£o
// * adicionados na geraÃ§Ã£o do certificado, devendo usar a codificaÃ§Ã£o dos campos jÃ¡ exsitentes na requisiÃ§Ã£o.
// */
//TEST_F(EncodingTest, PrintableUserID) {
//    ASSERT_TRUE(applyOne(LN_userId, V_ASN1_PRINTABLESTRING));
//}
