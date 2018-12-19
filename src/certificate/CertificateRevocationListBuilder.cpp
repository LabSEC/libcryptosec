#include <libcryptosec/certificate/CertificateRevocationListBuilder.h>

CertificateRevocationListBuilder::CertificateRevocationListBuilder()
{
	DateTime dateTime;
	this->crl = X509_CRL_new();
	this->setLastUpdate(dateTime);
	this->setNextUpdate(dateTime);
}

CertificateRevocationListBuilder::CertificateRevocationListBuilder(std::string pemEncoded)
		throw (EncodeException)
{
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateRevocationListBuilder::CertificateRevocationListBuilder");
	}
	if ((unsigned int)(BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size())) != pemEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "CertificateRevocationListBuilder::CertificateRevocationListBuilder");
	}
	this->crl = PEM_read_bio_X509_CRL(buffer, NULL, NULL, NULL);
	if (this->crl == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_DECODE, "CertificateRevocationListBuilder::CertificateRevocationListBuilder");
	}
	BIO_free(buffer);
}

CertificateRevocationListBuilder::CertificateRevocationListBuilder(ByteArray &derEncoded)
	throw (EncodeException)
{
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateRevocationListBuilder::CertificateRevocationListBuilder");
	}
	if ((unsigned int)(BIO_write(buffer, derEncoded.getDataPointer(), derEncoded.size())) != derEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "CertificateRevocationListBuilder::CertificateRevocationListBuilder");
	}
	this->crl = d2i_X509_CRL_bio(buffer, NULL); /* TODO: will the second parameter work fine ? */
	if (this->crl == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_DECODE, "CertificateRevocationListBuilder::CertificateRevocationListBuilder");
	}
	BIO_free(buffer);
}

CertificateRevocationListBuilder::CertificateRevocationListBuilder(const CertificateRevocationListBuilder& crl)
{
	this->crl = X509_CRL_dup(crl.getX509Crl());
}

CertificateRevocationListBuilder::~CertificateRevocationListBuilder()
{
	X509_CRL_free(this->crl);
}

std::string CertificateRevocationListBuilder::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string CertificateRevocationListBuilder::getXmlEncoded(std::string tab)
{
	std::string ret;
	char temp[11];
	std::vector<RevokedCertificate> revokedCertificates;
	unsigned int i;
	ret = tab + "<certificateRevocationList>\n";
	
	ret = tab + "\t<tbsCertList>\n";
		
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

		ret += tab + "\t\t<lastUpdate>" + this->getLastUpdate().getXmlEncoded() + "</lastUpdate>";

		ret += tab + "\t\t<nextUpdate>" + this->getNextUpdate().getXmlEncoded() + "</nextUpdate>";
		
		ret += tab + "\t\t<revokedCertificates>\n";
			revokedCertificates = this->getRevokedCertificate();
			for (i=0;i<revokedCertificates.size();i++)
			{
				ret += revokedCertificates.at(i).getXmlEncoded(tab + "\t\t\t");
			}
		ret += tab + "\t\t</revokedCertificates>\n";

	ret = tab + "\t</tbsCertList>\n";
	
	ret += tab + "</certificateRevocationList>\n";
	return ret;
}

void CertificateRevocationListBuilder::setSerialNumber(long serial)
		throw (CertificationException)
{
	ASN1_INTEGER* serialAsn1;
	int rc;
	serialAsn1 = ASN1_INTEGER_new();
	ASN1_INTEGER_set(serialAsn1, serial);
	rc = X509_CRL_add1_ext_i2d(this->crl, NID_crl_number, serialAsn1, 0, 0);
	ASN1_INTEGER_free(serialAsn1);
	if (rc != 1)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationListBuilder::setSerialNumber");
	}
}

void CertificateRevocationListBuilder::setSerialNumber(BigInteger serial)
		throw (CertificationException, BigIntegerException)
{
	int rc;
	rc = X509_CRL_add1_ext_i2d(this->crl, NID_crl_number, serial.getASN1Value(), 0, 0);
	if (rc != 1)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationListBuilder::setSerialNumber");
	}
}

long CertificateRevocationListBuilder::getSerialNumber()
		throw (CertificationException)
{
	ASN1_INTEGER *asn1Int;
	long ret;
	if (this->crl == NULL)
	{
		throw CertificationException(CertificationException::INVALID_CRL, "CertificateRevocationListBuilder::getSerialNumber");
	}
	asn1Int = (ASN1_INTEGER*) X509_CRL_get_ext_d2i(this->crl, NID_crl_number, 0, 0);
	if (asn1Int == NULL)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateRevocationListBuilder::getSerialNumber");
	}
	if (asn1Int->data == NULL)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationListBuilder::getSerialNumber");
	}
	ret = ASN1_INTEGER_get(asn1Int);
	if (ret < 0L)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationListBuilder::getSerialNumber");
	}
	return ret;
}

BigInteger CertificateRevocationListBuilder::getSerialNumberBigInt()
		throw (CertificationException, BigIntegerException)
{
	ASN1_INTEGER *asn1Int;
	if (this->crl == NULL)
	{
		throw CertificationException(CertificationException::INVALID_CRL, "CertificateRevocationListBuilder::getSerialNumber");
	}
	asn1Int = (ASN1_INTEGER*) X509_CRL_get_ext_d2i(this->crl, NID_crl_number, 0, 0);
	if (asn1Int == NULL)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateRevocationListBuilder::getSerialNumber");
	}
	if (asn1Int->data == NULL)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationListBuilder::getSerialNumber");
	}
	return BigInteger(asn1Int);
}

void CertificateRevocationListBuilder::setVersion(long version)
{
	X509_CRL_set_version(this->crl, version);
}

long CertificateRevocationListBuilder::getVersion()
		throw (CertificationException)
{
	long ret;
	/* Here, we have a problem!!! the return value 0 can be error and a valid value. */
	if (this->crl == NULL)
	{
		throw CertificationException(CertificationException::INVALID_CRL, "CertificateRevocationListBuilder::getVersion");
	}
	ret = X509_CRL_get_version(this->crl);
	if (ret < 0 || ret > 1)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateRevocationListBuilder::getVersion");
	}
	return ret;
}

void CertificateRevocationListBuilder::setIssuer(RDNSequence &issuer)
		throw (CertificationException)
{
	int rc;
	X509_NAME *name;
	name = issuer.getX509Name();
	rc = X509_CRL_set_issuer_name(this->crl, name);
	X509_NAME_free(name);
	if (!rc)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationListBuilder::setIssuer");
	}
}

void CertificateRevocationListBuilder::setIssuer(X509* issuer)
		throw (CertificationException)
{
	//TODO(lucasperin):
	int rc;
	//      X509_NAME *name;
	//      name = issuer.getX509Name();
	rc = X509_CRL_set_issuer_name(this->crl, X509_get_subject_name(issuer));
	//      X509_NAME_free(name);
	if (!rc)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationListBuilder::setIssuer");
	}
}

RDNSequence CertificateRevocationListBuilder::getIssuer()
{
	return RDNSequence(X509_CRL_get_issuer(this->crl));
}

void CertificateRevocationListBuilder::setLastUpdate(DateTime &dateTime)
{
	ASN1_TIME *asn1Time;
	
	/*
	 * Devido a um bug do firefox ao abrir CRL com datas em formato GeneralizedTime, mudou-se para UTC
	 * */
	//asn1Time = dateTime.getAsn1Time();
	asn1Time = dateTime.getUTCTime();
	X509_CRL_set_lastUpdate(this->crl, asn1Time);
	ASN1_TIME_free(asn1Time);
}

DateTime CertificateRevocationListBuilder::getLastUpdate()
{
	return DateTime(X509_CRL_get_lastUpdate(this->crl));
}

void CertificateRevocationListBuilder::setNextUpdate(DateTime &dateTime)
{
	ASN1_TIME *dateAsn1;
	
	/*
	 * Devido a um bug do firefox ao abrir CRL com datas em formato GeneralizedTime, mudou-se para UTC
	 * */
	//dateAsn1 = dateTime.getAsn1Time();
	dateAsn1 = dateTime.getAsn1Time();
	X509_CRL_set_nextUpdate(this->crl, dateAsn1);
	ASN1_TIME_free(dateAsn1);
}

DateTime CertificateRevocationListBuilder::getNextUpdate()
{
	return DateTime(X509_CRL_get_nextUpdate(this->crl));
}

void CertificateRevocationListBuilder::addRevokedCertificate(RevokedCertificate &revoked)
		throw (CertificationException)
{
	int rc;
//	X509_REVOKED *x509Revoked;
//	x509Revoked = revoked.getX509Revoked();
	rc = X509_CRL_add0_revoked(this->crl, revoked.getX509Revoked());
//	X509_REVOKED_free(x509Revoked);
	if (!rc)
    {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationListBuilder::addRevokedCertificate");
    }
}

void CertificateRevocationListBuilder::addRevokedCertificates(std::vector<RevokedCertificate> &revoked)
		throw (CertificationException)
{
	int rc;
	unsigned int i;
//	X509_REVOKED *x509Revoked;
	for (i=0;i<revoked.size();i++)
	{
//		x509Revoked = revoked.at(i).getX509Revoked();
		rc = X509_CRL_add0_revoked(this->crl, revoked.at(i).getX509Revoked());
//		X509_REVOKED_free(x509Revoked);
		if (!rc)
		{
			throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationListBuilder::addRevokedCertificate");
		}
	}
}

std::vector<RevokedCertificate> CertificateRevocationListBuilder::getRevokedCertificate()
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

CertificateRevocationList* CertificateRevocationListBuilder::sign(PrivateKey &privateKey, MessageDigest::Algorithm messageDigestAlgorithm)
		throw (CertificationException)
{
	int rc;
	CertificateRevocationList *ret;
	if (X509_CRL_get_ext_count(this->crl))
	{
		this->setVersion(1);
	}
	else
	{
		this->setVersion(0);
	}

        // TODO: We force Identity message digest for EdDSA to avoid changing callers which always pass digests.
        EVP_PKEY* pkey = privateKey.getEvpPkey();
        int pkeyType = EVP_PKEY_type(pkey->type);
        int nid25519 = OBJ_sn2nid("ED25519");
        int nid521 = OBJ_sn2nid("ED521");
        int nid448 = OBJ_sn2nid("ED448");
        if (pkeyType == nid25519 || pkeyType == nid521 || pkeyType == nid448) {
		messageDigestAlgorithm = MessageDigest::Identity;
        }

	rc = X509_CRL_sign(this->crl, privateKey.getEvpPkey(), MessageDigest::getMessageDigest(messageDigestAlgorithm));
	if (rc == 0)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRevocationListBuilder::sign");
    }
    ret = new CertificateRevocationList(this->crl);
    DateTime dateTime;
	this->crl = X509_CRL_new();
	this->setLastUpdate(dateTime);
	this->setNextUpdate(dateTime);
    return ret;
}

X509_CRL* CertificateRevocationListBuilder::getX509Crl() const
{
	return this->crl;
}

CertificateRevocationListBuilder& CertificateRevocationListBuilder::operator =(const CertificateRevocationListBuilder& value)
{
	if (this->crl)
	{
		X509_CRL_free(this->crl);
	}
    this->crl = X509_CRL_dup(value.getX509Crl());
    return (*this);
}

/// Martin: 14/09/07 
void CertificateRevocationListBuilder::addExtension(Extension& extension)
	throw (CertificationException)
{	
	X509_EXTENSION *ext;
	int rc;
	ext = extension.getX509Extension();
	rc = X509_CRL_add_ext(this->crl, ext, -1);
	if (!rc)
	{
		throw CertificationException(CertificationException::ADDING_EXTENSION, "CertificateRevocationListBuilder::addExtension");
	}
}

/// Martin: 14/09/07
void CertificateRevocationListBuilder::addExtensions(std::vector<Extension *> &extensions)
		throw (CertificationException)
{
	unsigned int i;
	for (i=0;i<extensions.size();i++)
	{
		Extension& ext = *(extensions.at(i));
		this->addExtension(ext);
	}
}

//Martin: 18/09/07
void CertificateRevocationListBuilder::replaceExtension(Extension &extension)
		throw (CertificationException)
{
	int position;
	X509_EXTENSION *ext;
	position = X509_CRL_get_ext_by_OBJ(this->crl, extension.getObjectIdentifier().getObjectIdentifier(), -1);
	if (position >= 0)
	{
		ext = X509_CRL_delete_ext(this->crl, position);
		X509_EXTENSION_free(ext);
	}
	this->addExtension(extension);
}

//Martin: 21/09/07
std::vector<Extension*> CertificateRevocationListBuilder::getExtension(Extension::Name extensionName)
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

//Martin: 26/09/07
std::vector<Extension*> CertificateRevocationListBuilder::getExtensions()
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
			case Extension::DELTA_CRL_INDICATOR:
				oneExt = new DeltaCRLIndicatorExtension(ext);							
				break;
			default:
				oneExt = new Extension(ext);
				break;
		}
		ret.push_back(oneExt);
	}
	return ret;
}

//Martin: 26/09/07
std::vector<Extension *> CertificateRevocationListBuilder::getUnknownExtensions()
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
