#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/RSAKeyPair.h>
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
        tmp.addEntry(RDNSequence::COMMON_NAME, "Common Name");
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
     *
     * @param expectedCodification Codificacao esperada.
     */
    void testStringCodificaton(int expectedCodification) {
        X509_NAME* after = X509_get_subject_name(cbuilder->getX509());
        for (int i = 0; i < X509_NAME_entry_count(after); i++) {
            X509_NAME_ENTRY* entry = X509_NAME_get_entry(after, i);
            if (OBJ_obj2nid(entry->object) != NID_countryName) {
            	int codification = entry->value->type;
            	ASSERT_EQ(codification, expectedCodification);
            }
        }
    }

    /*!
     * @brief Testa se a codificacao do certificado esta de acordo com o esperado.
     *
     * @param expectedCodification Codificação esperada.
     * @param cert Certificado exportado.
     */
    void testStringCodificaton(int expectedCodification, Certificate* cert) {
    	X509_NAME* after = X509_get_subject_name(cert->getX509());
    	for (int i = 0; i < X509_NAME_entry_count(after); i++) {
    		X509_NAME_ENTRY* entry = X509_NAME_get_entry(after, i);
    		if (OBJ_obj2nid(entry->object) != NID_countryName) {
    			int codification = entry->value->type;
    			ASSERT_EQ(codification, expectedCodification);
    		}
    	}
    }

    /*!
     * @brief Testa se os valores das entradas sao mantidos apos a geracao do certificado.
     *
     * @param r RDNSequence o qual se deseja comparar com rdn interno.
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

    void setPEMIncompletePrintable() {
    	using std::endl;
    	std::stringstream stream;
    	stream << "-----BEGIN CERTIFICATE REQUEST-----" << endl
    		   << "MIIC+TCCAeECAQAwQzESMBAGA1UEBxMJeXd5cmEgQUMyMRIwEAYDVQQDEwl5d3ly" << endl
			   << "YSBBQzIxGTAXBgNVBAwTEHRpdHVsbyB5d3lyYSBBQzIwggEiMA0GCSqGSIb3DQEB" << endl
			   << "AQUAA4IBDwAwggEKAoIBAQDVh+Mi3eOz0YXK6J9hqCCwSLhAVpCHqxnGoq4g6bzL" << endl
			   << "igClV5GbwIaKhMVuOS/0mdth+v4aBA1gVFMtpmR3xxFrDnaARjM5bwx1FKVyyZkF" << endl
			   << "boNwaUGVWwPNraNNlnwMtL6oeksTDMSBRKTp8Jeu+sOPetL09ek4Ys29VGgRyu7i" << endl
			   << "tE44fRiY0g+KxJfYN9DGPXv0dfJHhhu4D3UjvafAE0b8eiQT+4dlLw1euU1sJ8IF" << endl
			   << "1y0109Jh5hexbLczhGuaV7bnG3xP+rrObiQ1iuQOdFMTgv1HTVnCmMM9Phh1lMXH" << endl
			   << "5Sy8T1DZSfe0uekJpFuzbBTjzDQvb2ZYE7XM0/uoTWDDAgMBAAGgcTBvBgkqhkiG" << endl
			   << "9w0BCQ4xYjBgMB0GA1UdDgQWBBRuVgfS7weLK4LybliWkb+q6LcVMjAPBgNVHRMB" << endl
			   << "Af8EBTADAQH/MA8GA1UdDwEB/wQFAwMHH4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEG" << endl
			   << "CCsGAQUFBwMCMA0GCSqGSIb3DQEBDQUAA4IBAQCgEy2RmLok0IZizx9m++0v3YAn" << endl
			   << "eOD2VogN2QcncEz92uLsorRgGe5uwqRMxeHcJoFVzPNvYphe0R6lV4mxjDCgUIwT" << endl
			   << "hQl7GmCVEGMR+yCsgirYFHZz9jfuh7Q47ukSKo1sNrd50u8bFyUzu5CsnjEtJVE0" << endl
			   << "2gJBCuiyXuYBg/L4eZJDoJwY/iKyQKhRd68BtEUXFr7wF0U0CkggPU38Kiy/VQLH" << endl
			   << "XciyBd1S/BbTT9F8RW547rpeCF4oeqbN6kr2a+ykSIp3jLxz12vdXgGBVd+oBl6u" << endl
			   << "H42k/Nd8kyfCQCuZY0+8fQZv9lHLDIeCKV5EBrbz93esyWHFMmePiRXCCi3v" << endl
			   << "-----END CERTIFICATE REQUEST-----";
    	req_pem_encoded = stream.str();
    }

    void setPEMFullUTF8() {
    	using std::endl;
    	std::stringstream stream;
    	stream << "-----BEGIN CERTIFICATE REQUEST-----" << endl
    		   << "MIIDjzCCAncCAQAwgacxCzAJBgNVBAYTAkFBMRwwGgYDVQQKDBNvcmcgeXd5cmFB" << endl
			   << "QzEtMi41LjRjMR4wHAYDVQQLDBV1bm9yZyB5d3lyYUFDMS0yLjUuNGMxHzAdBgNV" << endl
			   << "BAgMFmVzdGFkbyB5d3lyYUFDMS0yLjUuNGMxGDAWBgNVBAMMD3l3eXJhQUMxLTIu" << endl
			   << "NS40YzEfMB0GA1UEDAwWdGl0dWxvIHl3eXJhQUMxLTIuNS40YzCCASIwDQYJKoZI" << endl
			   << "hvcNAQEBBQADggEPADCCAQoCggEBAJVY01W9ieCEfheLSrHcjxynj6fVwOyhGj1d" << endl
			   << "4PwSqe0l8M4vYPMGRuC0NqsvOrps+McdFXjdBoElDEZ+7UrxFXEW3jyNPw30aei9" << endl
			   << "3PtPWwS0UNj5ySs3nw3ybuZlmstFyeOldTbEFOctG/sVeHcz/pprVvqtCEXpLKtg" << endl
			   << "vtDgzjd68RRpJVIWIQ46HuoZZTRQomMiHZdkKKALkS0eAI7cKn1fVoLze2Hi/xnV" << endl
			   << "acPy6BN+nBhndUGye5KvmQUAI9hQk6UHORwLEuSW2tn8iWVopswmc1xMXez8sNPR" << endl
			   << "d2xwNnfA6xBZ1IZ0ZegzPLgegKQYraU93RofJa1bIWAHG/gtdx8CAwEAAaCBoTCB" << endl
			   << "ngYJKoZIhvcNAQkOMYGQMIGNMB0GA1UdDgQWBBSaXq9MlK7J+UHMhU84IwqvgUCY" << endl
			   << "qDAXBgNVHREEEDAOggxhc2Rhc2RzYWRhc2QwDwYDVR0TAQH/BAUwAwEB/zAPBgNV" << endl
			   << "HQ8BAf8EBQMDBz+AMDEGA1UdJQQqMCgGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYB" << endl
			   << "BQUHAwgGCCsGAQUFBwMJMA0GCSqGSIb3DQEBDQUAA4IBAQBhtwGISNB+nwpEJdB3" << endl
			   << "J1hYH28/61CpYhHGa5ysdCPaPpPw5P4+yrpC/iJFV4Lw/0pvauaTY8KVIZQnmLYq" << endl
			   << "rDB3Rv1d1qEC1owv1FLocnXVTfpyqLHtTZkNJ7ApHzUhUl+YCW+/cuIU+B9RxDug" << endl
			   << "H0511zsavlRO+9DkZYOC5hO/bDlWy1IdT51qepBWCRD2sHviMQRlzYrt/s2BpXKf" << endl
			   << "bhPfBWLL0wvV18WA3JmUOnjOCMXpHni9qoKS36eZVUr1pLbvwEmh0OLtSu9hhQGu" << endl
			   << "q3VVrMLsnvlcgBzTIZi4Nt52bqSHuYCrJh+pZdd3IPl5G0mra+HkuXnxKrbQM6YK" << endl
			   << "3aUS" << endl
			   << "-----END CERTIFICATE REQUEST-----";
    	req_pem_encoded = stream.str();
    }

    void setPEMIncompleteUTF8() {
    	using std::endl;
    	std::stringstream stream;
    	stream << "-----BEGIN CERTIFICATE REQUEST-----" << endl
    		   << "MIIC7jCCAdYCAQAwPzEjMCEGA1UEBwwabG9jYWxpZGFkZSBZd3lyYUFDMi0yLjUu" << endl
			   << "NGMxGDAWBgNVBAMMD1l3eXJhQUMyLTIuNS40YzCCASIwDQYJKoZIhvcNAQEBBQAD" << endl
			   << "ggEPADCCAQoCggEBAL9rgsnYC+gfpoYdOTKqFn6JWsL56lrc0qPuXfx15OJ0JF1s" << endl
			   << "tX3hMxkM+Jnq53kEOmVwKsVyCYvCBqzARFqzmSy2RtNr9UUlsQWDIcPel9c4Zzj4" << endl
			   << "cufd2ve7ChAEzFTR4j+gLZAnx7J7UdrLSSToRIkQpclGjFy11a1ldj7EXfZjn7HY" << endl
			   << "PDgYbS9b3GUp9zcJ8YkGMBiQJmCTVfsGL+81e/shxjnSI4AFc2FLKv6BgRH+g97c" << endl
			   << "gXzn45FmacudY8T1gqt4/j5SlwXNXMmnIpG8FRgnEmd5DInT7sb9wVVf1Ei/YCRP" << endl
			   << "vqCMAmPEx9sS5H+Smy8eI6CM64IFj2ElEqgbVk0CAwEAAaBqMGgGCSqGSIb3DQEJ" << endl
			   << "DjFbMFkwHQYDVR0OBBYEFBfmUjxv/PjEd9kCwPZOeV2mjPXsMA8GA1UdEwEB/wQF" << endl
			   << "MAMBAf8wJwYDVR0lBCAwHgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDAzAN" << endl
			   << "BgkqhkiG9w0BAQ0FAAOCAQEANczEwCLolws/rnLXFDJKgj3y4YmoH6L8BQ7tojwp" << endl
			   << "FFQolVhkBXFu80ZY6OnH6WhR2Ux/1H4rp7UC/m/yNcKA54Jru0VGm40YcbfZo9BT" << endl
			   << "gJoS0IZY9fjvalc4Wp7j2aeOAPoyPP75OrgZC3iGKxkZXe/0DmrmLgVPjUg3XtvE" << endl
			   << "BkkFtOBZxvjrv2fMWSKTgb4GkcF2Jl7DDx2TcZBltjxetyUmjUojhwyoCZoAJT4t" << endl
			   << "EyDVIOvHGRQYsl00eX+MWuqgzoosZkWc9LZTAasogMpeLQGG0016tfr4juPq2tOl" << endl
			   << "FNH73IwYynRBrS/XwxG/WZDPdyqf563Xq/FTF/CfsmJzrw==" << endl
    		   << "-----END CERTIFICATE REQUEST-----";
    	req_pem_encoded = stream.str();
    }

    /*!
     * @brief Converte um número representando um nid em um RDNSequence::EntryType.
     *
     * @param nid Nid OpenSSL.
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
TEST_F(EncodingTest, NonDefaultCodification) {
    setPEMFullPrintable();
    initialize();
    cbuilder->alterSubject(rdn);
    testStringCodificaton(V_ASN1_PRINTABLESTRING);
}

TEST_F(EncodingTest, DefaultCodification) {
    setPEMFullUTF8();
    initialize();
    cbuilder->alterSubject(rdn);
    testStringCodificaton(V_ASN1_UTF8STRING);
}

/*!
 * @brief Testa se o certificado mantem a formatacao antes de ser emitido, com um campo adicionado durante a emissao.
 */
TEST_F(EncodingTest, StringValues) {
    setPEMFullPrintable();
    initialize();
    cbuilder->alterSubject(rdn);
    testStringValues(req->getSubject());
}

/*!
 * @brief Testa se o certificado mantem a formatacao antes de ser emitido, com um campo adicionado durante a emissao.
 */
TEST_F(EncodingTest, AddedFieldNonDefaultCodification) {
    setPEMIncompletePrintable();
    initialize();
    rdn.addEntry(RDNSequence::ORGANIZATION_UNIT, "OUnitName");
    cbuilder->alterSubject(rdn);
    testStringCodificaton(V_ASN1_PRINTABLESTRING);
}

TEST_F(EncodingTest, AddedFieldDefaultCodification) {
    setPEMIncompleteUTF8();
    initialize();
    rdn.addEntry(RDNSequence::ORGANIZATION_UNIT, "OUnitName");
    cbuilder->alterSubject(rdn);
    testStringCodificaton(V_ASN1_UTF8STRING);
}

TEST_F(EncodingTest, ModifiedFieldNonDefaultCodification) {
    setPEMFullPrintable();
    initialize();
    modifyRDN();
    cbuilder->alterSubject(rdn);
    testStringCodificaton(V_ASN1_PRINTABLESTRING);
}

TEST_F(EncodingTest, ModifiedFieldDefaultCodification) {
    setPEMFullUTF8();
    initialize();
    modifyRDN();
    cbuilder->alterSubject(rdn);
    testStringCodificaton(V_ASN1_UTF8STRING);
}

TEST_F(EncodingTest, ModifiedFieldStringValues) {
    setPEMFullPrintable();
    initialize();
    modifyRDN();
    RDNSequence modified = rdn;
    cbuilder->alterSubject(rdn);
    testStringValues(modified);
}

TEST_F(EncodingTest, ExportedCertificateNonDefaultCodification) {
	setPEMFullPrintable();
	initialize();
	cbuilder->alterSubject(rdn);
	RSAKeyPair key = RSAKeyPair(4096);
	Certificate* cert = cbuilder->sign(*key.getPrivateKey(), MessageDigest::SHA512);
	testStringCodificaton(V_ASN1_PRINTABLESTRING, cert);
}

TEST_F(EncodingTest, ExportedCertificateDefaultCodification) {
	setPEMFullUTF8();
	initialize();
	cbuilder->alterSubject(rdn);
	RSAKeyPair key = RSAKeyPair(4096);
	Certificate* cert = cbuilder->sign(*key.getPrivateKey(), MessageDigest::SHA512);
	testStringCodificaton(V_ASN1_UTF8STRING, cert);
}

TEST_F(EncodingTest, ExportedCertificateStringValues) {
	setPEMFullPrintable();
	initialize();
	cbuilder->alterSubject(rdn);
	RSAKeyPair key = RSAKeyPair(4096);
	Certificate* cert = cbuilder->sign(*key.getPrivateKey(), MessageDigest::SHA512);
	testStringValues(cert->getSubject());
}
