#include <libcryptosec/certificate/CertificateBuilder.h>
#include <fstream>
#include "gtest.h"
#include <iostream>

class EncodingTest : public ::testing::Test {
protected:
    virtual void SetUp() {
        cbuilder = new CertificateBuilder();
        before = X509_NAME_new();
        after = X509_NAME_new();
    }

    virtual void TearDown() {
        delete cbuilder;
        X509_NAME_free(before);
        X509_NAME_free(after);
    }

    /*!
     * @brief Adiciona uma entrada de um X509_NAME com a codificação desejada.
     *
     * @param name Ponteiro para o X509_NAME.
     * @param entry Entrada a ser adicionada.
     * @param encoding Codificação desejada.
     */
    void insertEntry(X509_NAME* name, const char* entry, int encoding) {
        if (entry == LN_countryName) {
            X509_NAME_add_entry_by_txt(name, entry , V_ASN1_PRINTABLESTRING, (const unsigned char*)"CO", -1, -1, 0);
        }
        else {
            X509_NAME_add_entry_by_txt(name, entry , encoding, (const unsigned char*)entry, -1, -1, 0);
        }
    }

    /*!
     * @brief Adiciona as entradas DN de um X509_NAME com a codificação desejada.
     *
     * @param name Ponteiro para o X509_NAME.
     * @param encoding Codificação desejada.
     */
    void fillEntries(X509_NAME* name, int encoding) {
        insertEntry(name, LN_countryName, encoding);
        insertEntry(name, LN_stateOrProvinceName, encoding);
        insertEntry(name, LN_localityName, encoding);
        insertEntry(name, LN_organizationName, encoding);
        insertEntry(name, LN_organizationalUnitName, encoding);
        insertEntry(name, LN_commonName, encoding);
        insertEntry(name, LN_userId, encoding);
    }

    /*!
     * @brief Aplica um caso de teste com uma entrada preenchida com a codificação desejada e as restantes com a
     *        codificação padrão da versão OpenSSL.
     *
     * @param entry Entrada
     * @param encoding Codificação desejada.
     *
     * @return true se o caso de teste estiver correto, falso caso contrário.
     */
    bool applyOne(const char* entry, int encoding) {
        // create certificate:
        insertEntry(before, LN_commonName, encoding);    // common name é compulsório
        if (entry != LN_commonName) {
            insertEntry(before, entry, encoding);    // insere a entrada se não for common name
        }
        X509_set_subject_name(cbuilder->getX509(), X509_NAME_dup(before));

        // fill entries and apply alterSubject:
        fillEntries(before, MBSTRING_ASC);
        RDNSequence rdn(X509_NAME_dup(before));
        cbuilder->alterSubject(rdn);
        after = X509_NAME_dup(X509_get_subject_name(cbuilder->getX509()));

        return test();
    }

    /*!
     * @brief Aplica um caso de teste com todas as entradas preenchidas com a codificação desejada.
     *
     * @param encoding Codificação desejada.
     *
     * @return true se o caso de teste estiver correto, falso caso contrário.
     */
    bool applyAll(int encoding) {
        // create certificate:
        fillEntries(before, encoding);
        X509_set_subject_name(cbuilder->getX509(), X509_NAME_dup(before));

        // apply alterSubject:
        RDNSequence rdn(X509_NAME_dup(before));
        cbuilder->alterSubject(rdn);
        after = X509_NAME_dup(X509_get_subject_name(cbuilder->getX509()));

        return test();
    }

    /*!
     * @brief Testa se a codificação das entradas estão de acordo com o esperado.
     *
     * Testa se a codificação das entradas no certificado gerado estão de acordo com a primeira entrada commonName que é
     * obrigatória na geração da requisição.
     */
    bool test() {
        int encodingCommonName = X509_NAME_get_entry(before, X509_NAME_get_index_by_NID(nm, NID_commonName, -1));
        for (int i = 0; i < X509_NAME_entry_count(before); i++) {
            int encodingAfter = X509_NAME_get_entry(after, i)->value->type;
            if (encoding_after != encodingCommonName) {
                return false;
            }
        }
        return true;
    }

    CertificateBuilder* cbuilder;  //!< CertificateBuilder usado para aplicar a função testada.
    X509_NAME* before;  //!< Ponteiro para o X509_NAME antes de aplicar a função testada.
    X509_NAME* after;  //!< Ponteiro para o X509_NAME depois de aplicar a função testada.
};

/*!
 * @brief Teste usando todas as entradas preenchidas com codificação MBSTRING_ASC.
 *
 * Simula a situação onde os campos são preenchidos na geração do certificado. Na versão utilizada do OpenSSL, essa
 * codificação é equivalente a V_ASN1_UTF8STRING.
 */
 TEST_F(EncodingTest, MBStringFilled) {
     ASSERT_TRUE(applyAll(MBSTRING_ASC));
 }


/*!
 * @brief Teste usando todas as entradas preenchidas com codificação V_ASN1_PRINTABLESTRING.
 *
 * Simula a situação onde os campos são preenchidos na geração da requisição, devendo manter sua codificação no
 * certificado gerado.
 */
TEST_F(EncodingTest, PrintableFilled) {
    ASSERT_TRUE(applyAll(V_ASN1_PRINTABLESTRING));
}

/*!
 * @brief Teste usando as entradas commonName e countryName preenchidas com codificação V_ASN1_PRINTABLESTRING e as
 *        restantes com codificação MBSTRING_ASC.
 *
 * Simula a situação onde os campos Common Name e Country Name são preenchidos na geração da requisição e os restantes
 * são adicionados na geração do certificado, devendo usar a codificação dos campos já exsitentes na requisição.
 */
TEST_F(EncodingTest, PrintablecountryName) {
    ASSERT_TRUE(applyOne(LN_countryName, V_ASN1_PRINTABLESTRING));
}

/*!
 * @brief Teste usando as entradas commonName e stateOrProvinceName preenchidas com codificação V_ASN1_PRINTABLESTRING e
 *        as restantes com codificação MBSTRING_ASC.
 *
 * Simula a situação onde os campos Common Name e State or Province Name são preenchidos na geração da requisição e os
 * restantes são adicionados na geração do certificado, devendo usar a codificação dos campos já exsitentes na
 * requisição.
 */
TEST_F(EncodingTest, PrintableState) {
    ASSERT_TRUE(applyOne(LN_stateOrProvinceName, V_ASN1_PRINTABLESTRING));
}

/*!
 * @brief Teste usando as entradas commonName e localityName preenchidas com codificação V_ASN1_PRINTABLESTRING e as
 *        restantes com codificação MBSTRING_ASC.
 *
 * Simula a situação onde os campos Common Name e Locality Name são preenchidos na geração da requisição e os restantes
 * são adicionados na geração do certificado, devendo usar a codificação dos campos já exsitentes na requisição.
 */
TEST_F(EncodingTest, PrintableLocality) {
    ASSERT_TRUE(applyOne(LN_localityName, V_ASN1_PRINTABLESTRING));
}

/*!
 * @brief Teste usando as entradas commonName e organizationName preenchidas com codificação V_ASN1_PRINTABLESTRING e as
 *        restantes com codificação MBSTRING_ASC.
 *
 * Simula a situação onde os campos Common Name e Organization Name são preenchidos na geração da requisição e os
 * restantes são adicionados na geração do certificado, devendo usar a codificação dos campos já exsitentes na
 * requisição.
 */
TEST_F(EncodingTest, PrintableOrganization) {
    ASSERT_TRUE(applyOne(LN_organizationName, V_ASN1_PRINTABLESTRING));
}

/*!
 * @brief Teste usando as entradas commonName e organizationalUnitName preenchidas com codificação
 *        V_ASN1_PRINTABLESTRING e as restantes com codificação MBSTRING_ASC.
 *
 * Simula a situação onde os campos Common Name e Organizational Unit Name são preenchidos na geração da requisição e os
 * restantes são adicionados na geração do certificado, devendo usar a codificação dos campos já exsitentes na
 * requisição.
 */
TEST_F(EncodingTest, PrintableOrganizationalUnit) {
    ASSERT_TRUE(applyOne(LN_organizationalUnitName, V_ASN1_PRINTABLESTRING));
}

/*!
 * @brief Teste usando a entrada commonName preenchida com codificação V_ASN1_PRINTABLESTRING e asrestantes com
 *        codificação MBSTRING_ASC.
 *
 * Simula a situação onde apenas o campo Common Name é preenchido na geração da requisição e os restantes são
 * adicionados na geração do certificado, devendo usar a codificação dos campos já exsitentes na requisição.
 */
TEST_F(EncodingTest, PrintableCommonName) {
    ASSERT_TRUE(applyOne(LN_commonName, V_ASN1_PRINTABLESTRING));
}

/*!
 * @brief Teste usando as entradas commonName e userId preenchidas com codificação V_ASN1_PRINTABLESTRING e as
 *        restantes com codificação MBSTRING_ASC.
 *
 * Simula a situação onde os campos Common Name e User ID são preenchidos na geração da requisição e os restantes são
 * adicionados na geração do certificado, devendo usar a codificação dos campos já exsitentes na requisição.
 */
TEST_F(EncodingTest, PrintableUserID) {
    ASSERT_TRUE(applyOne(LN_userId, V_ASN1_PRINTABLESTRING));
}
