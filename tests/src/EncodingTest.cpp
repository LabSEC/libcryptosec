#include <libcryptosec/certificate/CertificateBuilder.h>
#include <fstream>
#include "gtest.h"
#include <iostream>

class EncodingTest : public ::testing::Test {
protected:
    virtual void SetUp() {
        cbuilder = new CertificateBuilder();
    }

    virtual void TearDown() {
        delete cbuilder;
    }

    CertificateBuilder* cbuilder;
    static X509_NAME* mbstring_asc;
    static X509_NAME* printable;
};

/*!
 *  @brief Função auxiliar para gerar um X509_NAME.
 *
 *  Cria um novo X509_NAME e insere entradas com a codificação desejada.
 *
 * @param encoding Codificação desejada.
 *
 * @return Ponteiro para o X509_NAME criado
 */
X509_NAME* make_X509_NAME(int encoding) {
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, SN_commonName, encoding, (const unsigned char*)"Common Name", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, SN_countryName, encoding, (const unsigned char*)"BR", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, SN_organizationName, encoding, (const unsigned char*)"Organization", -1, -1, 0);

    return name;
}

X509_NAME* EncodingTest::mbstring_asc = make_X509_NAME(MBSTRING_ASC);
X509_NAME* EncodingTest::printable = make_X509_NAME(V_ASN1_PRINTABLESTRING);

/*!
 *  @brief Teste usando codificação usando MBSTRING_ASC.
 *
 *  Simula a situação onde a codificação não é importante. MBSTRING_ASC é a codificação padrão na biblioteca
 */
 TEST_F(EncodingTest, MBStringEncoding) {
     RDNSequence rdn(mbstring_asc);
     cbuilder->alterSubject(rdn);
     X509_NAME* X509_after = X509_get_subject_name(cbuilder->getX509());

     for (int i = 0; i < X509_NAME_entry_count(X509_after); i++) {
         int before = X509_NAME_get_entry(mbstring_asc, i)->value->type;
         int after = X509_NAME_get_entry(X509_after, i)->value->type;
         ASSERT_EQ(before, after);
     }
 }


/*!
 * @bried Teste usando codificação V_ASN1_PRINTABLESTRING
 *
 *  Simula a situação onde a requisição precisa manter a sua codificação original
 */
TEST_F(EncodingTest, PrintableStringEncoding) {
    RDNSequence rdn(printable);
    cbuilder->alterSubject(rdn);
    X509_NAME* X509_after = X509_get_subject_name(cbuilder->getX509());

    for (int i = 0; i < X509_NAME_entry_count(X509_after); i++) {
        int before = X509_NAME_get_entry(printable, i)->value->type;
        int after = X509_NAME_get_entry(X509_after, i)->value->type;
        ASSERT_EQ(before, after);
    }
}
