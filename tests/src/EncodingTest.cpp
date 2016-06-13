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

    void insertEntry(X509_NAME* name, const char* entry, int encoding) {
        if (entry == LN_countryName) {
            X509_NAME_add_entry_by_txt(name, entry , V_ASN1_PRINTABLESTRING, (const unsigned char*)"CO", -1, -1, 0);
        }
        else {
            X509_NAME_add_entry_by_txt(name, entry , encoding, (const unsigned char*)entry, -1, -1, 0);
        }
    }

    void fillEntries(X509_NAME* name, int encoding) {
        insertEntry(name, LN_countryName, encoding);
        insertEntry(name, LN_stateOrProvinceName, encoding);
        insertEntry(name, LN_localityName, encoding);
        insertEntry(name, LN_organizationName, encoding);
        insertEntry(name, LN_organizationalUnitName, encoding);
        insertEntry(name, LN_commonName, encoding);
        insertEntry(name, LN_userId, encoding);
    }

    bool applyOne(const char* entry, int encoding) {
        // create certificate:
        insertEntry(before, entry, encoding);
        X509_set_subject_name(cbuilder->getX509(), X509_NAME_dup(before));

        // apply alterSubject:
        fillEntries(before, MBSTRING_ASC);
        insertEntry(before, entry, encoding);
        RDNSequence rdn(X509_NAME_dup(before));
        cbuilder->alterSubject(rdn);
        after = X509_NAME_dup(X509_get_subject_name(cbuilder->getX509()));

        return test();
    }

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

    bool test() {
        for (int i = 0; i < X509_NAME_entry_count(before); i++) {
            int encoding_before = X509_NAME_get_entry(before, i)->value->type;
            int encoding_after = X509_NAME_get_entry(after, i)->value->type;
            std::cout << "before: " << encoding_before << '\n';
            std::cout << "after:  " << encoding_after << '\n';
            if (encoding_after != encoding_before) {
                return false;
            }
        }
        return true;
    }

    CertificateBuilder* cbuilder;
    X509_NAME* before;
    X509_NAME* after;
};

/*!
 *  @brief Teste usando codificação usando MBSTRING_ASC.
 *
 *  Simula a situação onde a codificação não é importante. MBSTRING_ASC é a codificação padrão na biblioteca
 */
 TEST_F(EncodingTest, MBStringFilled) {
     ASSERT_TRUE(applyAll(MBSTRING_ASC));
 }


/*!
 * @bried Teste usando codificação V_ASN1_PRINTABLESTRING
 *
 *  Simula a situação onde a requisição precisa manter a sua codificação original
 */
TEST_F(EncodingTest, PrintableFilled) {
    ASSERT_TRUE(applyAll(V_ASN1_PRINTABLESTRING));
}

TEST_F(EncodingTest, PrintablecountryName) {
    ASSERT_TRUE(applyOne(LN_countryName, V_ASN1_PRINTABLESTRING));
}

TEST_F(EncodingTest, PrintableState) {
    ASSERT_TRUE(applyOne(LN_stateOrProvinceName, V_ASN1_PRINTABLESTRING));
}

TEST_F(EncodingTest, PrintableLocality) {
    ASSERT_TRUE(applyOne(LN_localityName, V_ASN1_PRINTABLESTRING));
}

TEST_F(EncodingTest, PrintableOrganization) {
    ASSERT_TRUE(applyOne(LN_organizationName, V_ASN1_PRINTABLESTRING));
}

TEST_F(EncodingTest, PrintableOrganizationalUnit) {
    ASSERT_TRUE(applyOne(LN_organizationalUnitName, V_ASN1_PRINTABLESTRING));
}

TEST_F(EncodingTest, PrintableCommonName) {
    ASSERT_TRUE(applyOne(LN_commonName, V_ASN1_PRINTABLESTRING));
}

TEST_F(EncodingTest, PrintableUserID) {
    ASSERT_TRUE(applyOne(LN_userId, V_ASN1_PRINTABLESTRING));
}
