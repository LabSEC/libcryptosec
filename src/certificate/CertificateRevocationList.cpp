#include <libcryptosec/certificate/CertificateRevocationList.h>

CertificateRevocationList::CertificateRevocationList(X509_CRL *crl)
{
	this->crl = crl;
}

CertificateRevocationList::CertificateRevocationList(std::string pemEncoded)
		throw (EncodeException)
{
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateRevocationList::CertificateRevocationList");
	}
	if ((unsigned int)(BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size())) != pemEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "CertificateRevocationList::CertificateRevocationList");
	}
	this->crl = PEM_read_bio_X509_CRL(buffer, NULL, NULL, NULL);
	if (this->crl == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_DECODE, "CertificateBuilder::CertificateBuilder");
	}
	BIO_free(buffer);
}

CertificateRevocationList::CertificateRevocationList(ByteArray &derEncoded)
	throw (EncodeException)
{
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateRevocationList::CertificateRevocationList");
	}
	if ((unsigned int)(BIO_write(buffer, derEncoded.getDataPointer(), derEncoded.size())) != derEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "CertificateRevocationList::CertificateRevocationList");
	}
	this->crl = d2i_X509_CRL_bio(buffer, NULL); /* TODO: will the second parameter work fine ? */
	if (this->crl == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_DECODE, "CertificateRevocationList::CertificateRevocationList");
	}
	BIO_free(buffer);
}

CertificateRevocationList::CertificateRevocationList(const CertificateRevocationList& crl)
{
	this->crl = X509_CRL_dup(crl.getX509Crl());
}

CertificateRevocationList::~CertificateRevocationList()
{
	X509_CRL_free(this->crl);
}

std::string CertificateRevocationList::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string CertificateRevocationList::getXmlEncoded(std::string tab)
{
	std::string ret, string;
	ByteArray data;
	char temp[11];
	std::vector<RevokedCertificate> revokedCertificates;
	unsigned int i;
	ret = tab + "<certificateRevocationList>\n";
	
	ret += tab + "\t<tbsCertList>\n";
		
		try /* version */
		{
			sprintf(temp, "%d", (int)this->getVersion());
			ret += tab + "\t\t<version>" + temp + "</version>\n";
		}
		catch (...)
		{
		}
		try /* Serial Number */
		{
			sprintf(temp, "%d", (int)this->getSerialNumber());
			ret += tab + "\t\t<serialNumber>" + temp + "</serialNumber>\n";
		}
		catch (...)
		{
		}
		ret += tab + "\t\t<issuer>\n";
		
			ret += (this->getIssuer()).getXmlEncoded("\t\t\t");
			
		ret += tab + "\t\t</issuer>\n";

		ret += tab + "\t\t<lastUpdate>" + this->getLastUpdate().getXmlEncoded() + "</lastUpdate>\n";

		ret += tab + "\t\t<nextUpdate>" + this->getNextUpdate().getXmlEncoded() + "</nextUpdate>\n";
		
		ret += tab + "\t\t<revokedCertificates>\n";
			revokedCertificates = this->getRevokedCertificate();
			for (i=0;i<revokedCertificates.size();i++)
			{
				ret += revokedCertificates.at(i).getXmlEncoded(tab + "\t\t\t");
			}
		ret += tab + "\t\t</revokedCertificates>\n";

	ret += tab + "\t</tbsCertList>\n";

	ret += tab + "\t<signatureAlgorithm>\n";
		string = OBJ_nid2ln(OBJ_obj2nid(this->crl->sig_alg->algorithm));
		ret += tab + "\t\t<algorithm>" + string + "</algorithm>\n";
	ret += tab + "\t</signatureAlgorithm>\n";
	
	data = ByteArray(this->crl->signature->data, this->crl->signature->length); 
	string = Base64::encode(data);
	ret += tab + "\t<signatureValue>" + string + "</signatureValue>\n";

	ret += tab + "</certificateRevocationList>\n";
	return ret;
}

std::string CertificateRevocationList::getPemEncoded()
		throw (EncodeException)
{
	BIO *buffer;
	int ndata, wrote;
	std::string ret;
	ByteArray *tmp;
	unsigned char *data;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateRevocationList::getPemEncoded");
	}
	wrote = PEM_write_bio_X509_CRL(buffer, this->crl);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_ENCODE, "CertificateRevocationList::getPemEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "CertificateRevocationList::getPemEncoded");
	}
//	std::cout << "data: " << data << std::endl;
	tmp = new ByteArray(data, ndata);
	ret = tmp->toString();
	BIO_free(buffer);
	delete tmp;
	return ret;
}

ByteArray CertificateRevocationList::getDerEncoded()
		throw (EncodeException)
{
	BIO *buffer;
	int ndata, wrote;
	ByteArray ret;
	unsigned char *data;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateRevocationList::getDerEncoded");
	}
	wrote = i2d_X509_CRL_bio(buffer, this->crl);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_ENCODE, "CertificateRevocationList::getDerEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "CertificateRevocationList::getDerEncoded");
	}
	ret = ByteArray(data, ndata);
	BIO_free(buffer);
	return ret;
}

long CertificateRevocationList::getSerialNumber()
		throw (CertificationException)
{
	ASN1_INTEGER *asn1Int;
	long ret;
	if (this->crl == NULL)
	{
		throw CertificationException(CertificationException::INVALID_CRL, "CertificateRevocationList::getSerialNumber");
	}
	asn1Int = (ASN1_INTEGER*) X509_CRL_get_ext_d2i(this->crl, NID_crl_number, 0, 0);
	if (asn1Int == NULL)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateRevocationList::getSerialNumber");
	}
	if (asn1Int->data == NULL)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationList::getSerialNumber");
	}
	ret = ASN1_INTEGER_get(asn1Int);
	if (ret < 0L)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationList::getSerialNumber");
	}
	return ret;
}

BigInteger CertificateRevocationList::getSerialNumberBigInt()
	throw (CertificationException, BigIntegerException)
{
	ASN1_INTEGER *asn1Int;
	if (this->crl == NULL)
	{
		throw CertificationException(CertificationException::INVALID_CRL, "CertificateRevocationList::getSerialNumber");
	}
	asn1Int = (ASN1_INTEGER*) X509_CRL_get_ext_d2i(this->crl, NID_crl_number, 0, 0);
	if (asn1Int == NULL)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateRevocationList::getSerialNumber");
	}
	if (asn1Int->data == NULL)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationList::getSerialNumber");
	}
	return BigInteger(asn1Int);
}

long CertificateRevocationList::getBaseCRLNumber()
		throw (CertificationException)
{
	ASN1_INTEGER *asn1Int;
	long ret;
	if (this->crl == NULL)
	{
		throw CertificationException(CertificationException::INVALID_CRL, "CertificateRevocationList::getBaseCRLNumber");
	}
	asn1Int = (ASN1_INTEGER*) X509_CRL_get_ext_d2i(this->crl, NID_delta_crl, 0, 0);
	if (asn1Int == NULL)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateRevocationList::getBaseCRLNumber");
	}
	if (asn1Int->data == NULL)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationList::getBaseCRLNumber");
	}
	ret = ASN1_INTEGER_get(asn1Int);
	if (ret < 0L)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationList::getBaseCRLNumber");
	}
	return ret;
}

BigInteger CertificateRevocationList::getBaseCRLNumberBigInt()
	throw (CertificationException, BigIntegerException)
{
	ASN1_INTEGER *asn1Int;
	if (this->crl == NULL)
	{
		throw CertificationException(CertificationException::INVALID_CRL, "CertificateRevocationList::getBaseCRLNumberBigInt");
	}
	asn1Int = (ASN1_INTEGER*) X509_CRL_get_ext_d2i(this->crl, NID_delta_crl, 0, 0);
	if (asn1Int == NULL)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateRevocationList::getBaseCRLNumberBigInt");
	}
	if (asn1Int->data == NULL)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationList::getBaseCRLNumberBigInt");
	}
	return BigInteger(asn1Int);
}


long CertificateRevocationList::getVersion()
		throw (CertificationException)
{
	long ret;
	/* Here, we have a problem!!! the return value 0 can be error and a valid value. */
	if (this->crl == NULL)
	{
		throw CertificationException(CertificationException::INVALID_CRL, "CertificateRevocationList::getVersion");
	}
	ret = X509_CRL_get_version(this->crl);
	if (ret < 0 || ret > 1)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateRevocationList::getVersion");
	}
	return ret;
}

RDNSequence CertificateRevocationList::getIssuer()
{
	return RDNSequence(X509_CRL_get_issuer(this->crl));
}

DateTime CertificateRevocationList::getLastUpdate()
{
	return DateTime(X509_CRL_get_lastUpdate(this->crl));
}

DateTime CertificateRevocationList::getNextUpdate()
{
	return DateTime(X509_CRL_get_nextUpdate(this->crl));
}

std::vector<RevokedCertificate> CertificateRevocationList::getRevokedCertificate()
{
	std::vector<RevokedCertificate> ret;
	int size, i;
	X509_REVOKED *revoked;
    STACK_OF(X509_REVOKED)* revokedStack = X509_CRL_get_REVOKED(this->crl);
    size = sk_X509_REVOKED_num(revokedStack);
    for (i=0;i<size;i++)
    {
    	revoked = sk_X509_REVOKED_value(revokedStack, i);
    	ret.push_back(RevokedCertificate(revoked));
    }
    return ret;
}

bool CertificateRevocationList::verify(PublicKey &publicKey)
{
	int rc;
	rc = X509_CRL_verify(this->crl, publicKey.getEvpPkey());
	return (rc?1:0);
}

X509_CRL* CertificateRevocationList::getX509Crl() const
{
	return this->crl;
}

CertificateRevocationList& CertificateRevocationList::operator =(const CertificateRevocationList& value)
{
	if (this->crl)
	{
		X509_CRL_free(this->crl);
	}
    this->crl = X509_CRL_dup(value.getX509Crl());
    return (*this);
}

std::vector<Extension*> CertificateRevocationList::getExtension(Extension::Name extensionName)
{
	int next, i;
	X509_EXTENSION *ext;
	std::vector<Extension *> ret;
	Extension *oneExt;
	next = X509_CRL_get_ext_count(this->crl);
	for (i=0;i<next;i++)
	{
		ext = X509_CRL_get_ext(this->crl, i);
		if (Extension::getName(ext) == extensionName)
		{
			switch (Extension::getName(ext))
			{
				case Extension::KEY_USAGE:
					oneExt = new KeyUsageExtension(ext);
					break;
				case Extension::EXTENDED_KEY_USAGE:
					oneExt = new ExtendedKeyUsageExtension(ext);
					break;
				case Extension::AUTHORITY_KEY_IDENTIFIER:
					oneExt = new AuthorityKeyIdentifierExtension(ext);
					break;
				case Extension::CRL_DISTRIBUTION_POINTS:
					oneExt = new CRLDistributionPointsExtension(ext);
					break;
				case Extension::AUTHORITY_INFORMATION_ACCESS:
					oneExt = new AuthorityInformationAccessExtension(ext);
					break;
				case Extension::BASIC_CONSTRAINTS:
					oneExt = new BasicConstraintsExtension(ext);
					break;
				case Extension::CERTIFICATE_POLICIES:
					oneExt = new CertificatePoliciesExtension(ext);
					break;
				case Extension::ISSUER_ALTERNATIVE_NAME:
					oneExt = new IssuerAlternativeNameExtension(ext);
					break;
				case Extension::SUBJECT_ALTERNATIVE_NAME:
					oneExt = new SubjectAlternativeNameExtension(ext);
					break;
				case Extension::SUBJECT_INFORMATION_ACCESS:
					oneExt = new SubjectInformationAccessExtension(ext);
					break;
				case Extension::SUBJECT_KEY_IDENTIFIER:
					oneExt = new SubjectKeyIdentifierExtension(ext);
					break;
				case Extension::CRL_NUMBER:
					oneExt = new CRLNumberExtension(ext);
					break;
				case Extension::DELTA_CRL_INDICATOR:
					oneExt = new DeltaCRLIndicatorExtension(ext);
					break;
				default:
					oneExt = new Extension(ext);
					break;
			}
			ret.push_back(oneExt);
		}
	}
	return ret;
}

std::vector<Extension*> CertificateRevocationList::getExtensions()
{
	int next, i;
	X509_EXTENSION *ext;
	std::vector<Extension *> ret;
	Extension *oneExt;
	next = X509_CRL_get_ext_count(this->crl);
	for (i=0;i<next;i++)
	{
		ext = X509_CRL_get_ext(this->crl, i);
		switch (Extension::getName(ext))
		{
			case Extension::KEY_USAGE:
				oneExt = new KeyUsageExtension(ext);
				break;
			case Extension::EXTENDED_KEY_USAGE:
				oneExt = new ExtendedKeyUsageExtension(ext);
				break;
			case Extension::AUTHORITY_KEY_IDENTIFIER:
				oneExt = new AuthorityKeyIdentifierExtension(ext);
				break;
			case Extension::CRL_DISTRIBUTION_POINTS:
				oneExt = new CRLDistributionPointsExtension(ext);
				break;
			case Extension::AUTHORITY_INFORMATION_ACCESS:
				oneExt = new AuthorityInformationAccessExtension(ext);
				break;
			case Extension::BASIC_CONSTRAINTS:
				oneExt = new BasicConstraintsExtension(ext);
				break;
			case Extension::CERTIFICATE_POLICIES:
				oneExt = new CertificatePoliciesExtension(ext);
				break;
			case Extension::ISSUER_ALTERNATIVE_NAME:
				oneExt = new IssuerAlternativeNameExtension(ext);
				break;
			case Extension::SUBJECT_ALTERNATIVE_NAME:
				oneExt = new SubjectAlternativeNameExtension(ext);
				break;
			case Extension::SUBJECT_INFORMATION_ACCESS:
				oneExt = new SubjectInformationAccessExtension(ext);
				break;
			case Extension::SUBJECT_KEY_IDENTIFIER:
				oneExt = new SubjectKeyIdentifierExtension(ext);
				break;
			case Extension::CRL_NUMBER:
				oneExt = new CRLNumberExtension(ext);
				break;
			default:
				oneExt = new Extension(ext);
				break;
		}
		ret.push_back(oneExt);
	}
	return ret;
}

std::vector<Extension *> CertificateRevocationList::getUnknownExtensions()
{
	int next, i;
	X509_EXTENSION *ext;
	std::vector<Extension *> ret;
	Extension *oneExt;
	next = X509_CRL_get_ext_count(this->crl);
	for (i=0;i<next;i++)
	{
		ext = X509_CRL_get_ext(this->crl, i);
		switch (Extension::getName(ext))
		{
			case Extension::UNKNOWN:
				oneExt = new Extension(ext);
				ret.push_back(oneExt);
			default:
				break;
		}
	}
	return ret;
}
