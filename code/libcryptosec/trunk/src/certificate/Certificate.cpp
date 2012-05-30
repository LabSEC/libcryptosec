#include <libcryptosec/certificate/Certificate.h>

Certificate::Certificate(X509 *cert)
{
	this->cert = cert;
}

Certificate::Certificate(std::string pemEncoded)
		throw (EncodeException)
{
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "Certificate::Certificate");
	}
	if ((unsigned int)(BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size())) != pemEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "Certificate::Certificate");
	}
	this->cert = PEM_read_bio_X509(buffer, NULL, NULL, NULL);
	if (this->cert == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_DECODE, "Certificate::Certificate");
	}
	BIO_free(buffer);
}

Certificate::Certificate(ByteArray &derEncoded)
	throw (EncodeException)
{
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "Certificate::Certificate");
	}
	if ((unsigned int)(BIO_write(buffer, derEncoded.getDataPointer(), derEncoded.size())) != derEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "Certificate::Certificate");
	}
	this->cert = d2i_X509_bio(buffer, NULL); /* TODO: will the second parameter work fine ? */
	if (this->cert == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_DECODE, "Certificate::Certificate");
	}
	BIO_free(buffer);
}

Certificate::Certificate(const Certificate& cert)
{
	this->cert = X509_dup(cert.getX509());
}

Certificate::~Certificate()
{
	X509_free(this->cert);
	this->cert = NULL;
}

std::string Certificate::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string Certificate::getXmlEncoded(std::string tab)
{
	std::string ret, string;
	ByteArray data;
	char temp[15];
	long value;
	std::vector<Extension *> extensions;
	unsigned int i;

	ret = "<?xml version=\"1.0\"?>\n";
	ret += "<certificate>\n";
	ret += "\t<tbsCertificate>\n";
		try /* version */
		{
			value = this->getVersion();
			sprintf(temp, "%d", (int)value);
			string = temp;
			ret += "\t\t<version>" + string + "</version>\n";
		}
		catch (...)
		{
		}
		try /* Serial Number */
		{
			value = this->getSerialNumber();
			sprintf(temp, "%d", (int)value);
			string = temp;
			ret += "\t\t<serialNumber>" + string + "</serialNumber>\n";
		}
		catch (...)
		{
		}
		string = OBJ_nid2ln(OBJ_obj2nid(this->cert->sig_alg->algorithm));
		ret += "\t\t<signature>" + string + "</signature>\n";

		ret += "\t\t<issuer>\n";
			try
			{
				ret += (this->getIssuer()).getXmlEncoded("\t\t\t");
			}
			catch (...)
			{
			}
		ret += "\t\t</issuer>\n";

		ret += "\t\t<validity>\n";
			try
			{
				ret += "\t\t\t<notBefore>" + ((this->getNotBefore()).getXmlEncoded()) + "</notBefore>\n";
			}
			catch (...)
			{
			}
			try
			{
				ret += "\t\t\t<notAfter>" + ((this->getNotAfter()).getXmlEncoded()) + "</notAfter>\n";
			}
			catch (...)
			{
			}
		ret += "\t\t</validity>\n";

		ret += "\t\t<subject>\n";
			try
			{
				ret += (this->getSubject()).getXmlEncoded("\t\t\t");
			}
			catch (...)
			{
			}
		ret += "\t\t</subject>\n";

		ret += "\t\t<subjectPublicKeyInfo>\n";
			string = OBJ_nid2ln(OBJ_obj2nid(this->cert->cert_info->key->algor->algorithm));
			ret += "\t\t\t<algorithm>" + string + "</algorithm>\n";
			data = ByteArray(this->cert->cert_info->key->public_key->data, this->cert->cert_info->key->public_key->length);
			string = Base64::encode(data);
			ret += "\t\t\t<subjectPublicKey>" + string + "</subjectPublicKey>\n";
		ret += "\t\t</subjectPublicKeyInfo>\n";

		if (this->cert->cert_info->issuerUID)
		{
			data = ByteArray(this->cert->cert_info->issuerUID->data, this->cert->cert_info->issuerUID->length);
			string = Base64::encode(data);
			ret += "\t\t<issuerUniqueID>" + string + "</issuerUniqueID>\n";
		}
		if (this->cert->cert_info->subjectUID)
		{
			data = ByteArray(this->cert->cert_info->subjectUID->data, this->cert->cert_info->subjectUID->length);
			string = Base64::encode(data);
			ret += "\t\t<subjectUniqueID>" + string + "</subjectUniqueID>\n";
		}

		ret += "\t\t<extensions>\n";
		extensions = this->getExtensions();
		for (i=0;i<extensions.size();i++)
		{
			ret += extensions.at(i)->getXmlEncoded("\t\t\t");
			delete extensions.at(i);
		}
		ret += "\t\t</extensions>\n";

	ret += "\t</tbsCertificate>\n";

	ret += "\t<signatureAlgorithm>\n";
		string = OBJ_nid2ln(OBJ_obj2nid(this->cert->sig_alg->algorithm));
		ret += "\t\t<algorithm>" + string + "</algorithm>\n";
	ret += "\t</signatureAlgorithm>\n";

	data = ByteArray(this->cert->signature->data, this->cert->signature->length);
	string = Base64::encode(data);
	ret += "\t<signatureValue>" + string + "</signatureValue>\n";

	ret += "</certificate>\n";
	return ret;
}

std::string Certificate::toXml(std::string tab)
{
	std::string ret, string;
	ByteArray data;
	char temp[15];
	long value;
	std::vector<Extension *> extensions;
	unsigned int i;

	ret = "<?xml version=\"1.0\"?>\n";
	ret += "<certificate>\n";
	ret += "\t<tbsCertificate>\n";
		try /* version */
		{
			value = this->getVersion();
			sprintf(temp, "%d", (int)value);
			string = temp;
			ret += "\t\t<version>" + string + "</version>\n";
		}
		catch (...)
		{
		}
		try /* Serial Number */
		{
			ret += "\t\t<serialNumber>" + this->getSerialNumberBigInt().toDec() + "</serialNumber>\n";
		}
		catch (...)
		{
		}
		string = OBJ_nid2ln(OBJ_obj2nid(this->cert->sig_alg->algorithm));
		ret += "\t\t<signature>" + string + "</signature>\n";

		ret += "\t\t<issuer>\n";
			try
			{
				ret += (this->getIssuer()).getXmlEncoded("\t\t\t");
			}
			catch (...)
			{
			}
		ret += "\t\t</issuer>\n";

		ret += "\t\t<validity>\n";
			try
			{
				ret += "\t\t\t<notBefore>" + ((this->getNotBefore()).getXmlEncoded()) + "</notBefore>\n";
			}
			catch (...)
			{
			}
			try
			{
				ret += "\t\t\t<notAfter>" + ((this->getNotAfter()).getXmlEncoded()) + "</notAfter>\n";
			}
			catch (...)
			{
			}
		ret += "\t\t</validity>\n";

		ret += "\t\t<subject>\n";
			try
			{
				ret += (this->getSubject()).getXmlEncoded("\t\t\t");
			}
			catch (...)
			{
			}
		ret += "\t\t</subject>\n";

		ret += "\t\t<subjectPublicKeyInfo>\n";
			string = OBJ_nid2ln(OBJ_obj2nid(this->cert->cert_info->key->algor->algorithm));
			ret += "\t\t\t<algorithm>" + string + "</algorithm>\n";
			data = ByteArray(this->cert->cert_info->key->public_key->data, this->cert->cert_info->key->public_key->length);
			string = Base64::encode(data);
			ret += "\t\t\t<subjectPublicKey>" + string + "</subjectPublicKey>\n";
		ret += "\t\t</subjectPublicKeyInfo>\n";

		if (this->cert->cert_info->issuerUID)
		{
			data = ByteArray(this->cert->cert_info->issuerUID->data, this->cert->cert_info->issuerUID->length);
			string = Base64::encode(data);
			ret += "\t\t<issuerUniqueID>" + string + "</issuerUniqueID>\n";
		}
		if (this->cert->cert_info->subjectUID)
		{
			data = ByteArray(this->cert->cert_info->subjectUID->data, this->cert->cert_info->subjectUID->length);
			string = Base64::encode(data);
			ret += "\t\t<subjectUniqueID>" + string + "</subjectUniqueID>\n";
		}

		ret += "\t\t<extensions>\n";
		extensions = this->getExtensions();
		for (i=0;i<extensions.size();i++)
		{
			ret += extensions.at(i)->toXml("\t\t\t");
			delete extensions.at(i);
		}
		ret += "\t\t</extensions>\n";

	ret += "\t</tbsCertificate>\n";

	ret += "\t<signatureAlgorithm>\n";
		string = OBJ_nid2ln(OBJ_obj2nid(this->cert->sig_alg->algorithm));
		ret += "\t\t<algorithm>" + string + "</algorithm>\n";
	ret += "\t</signatureAlgorithm>\n";

	data = ByteArray(this->cert->signature->data, this->cert->signature->length);
	string = Base64::encode(data);
	ret += "\t<signatureValue>" + string + "</signatureValue>\n";

	ret += "</certificate>\n";
	return ret;

}

std::string Certificate::getPemEncoded() const
		throw (EncodeException)
{
	BIO *buffer;
	int ndata, wrote;
	std::string ret;
	ByteArray *retTemp;
	unsigned char *data;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "Certificate::getPemEncoded");
	}
	wrote = PEM_write_bio_X509(buffer, this->cert);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_ENCODE, "Certificate::getPemEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "Certificate::getPemEncoded");
	}
	retTemp = new ByteArray(data, ndata);
	ret = retTemp->toString();
	delete retTemp;
	BIO_free(buffer);
	return ret;
}

ByteArray Certificate::getDerEncoded() const
		throw (EncodeException)
{
	BIO *buffer;
	int ndata, wrote;
	ByteArray ret;
	unsigned char *data;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "Certificate::getDerEncoded");
	}
	wrote = i2d_X509_bio(buffer, this->cert);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_ENCODE, "Certificate::getDerEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "Certificate::getDerEncoded");
	}
	ret = ByteArray(data, ndata);
	BIO_free(buffer);
	return ret;
}

long int Certificate::getSerialNumber() throw (CertificationException)
{
	ASN1_INTEGER *asn1Int;
	long ret;
	if (this->cert == NULL)
	{
		throw CertificationException(CertificationException::INVALID_CERTIFICATE, "Certificate::getSerialNumber");
	}
	/* Here, we have a problem!!! the return value -1 can be error and a valid value. */
	asn1Int = X509_get_serialNumber(this->cert);
	if (asn1Int == NULL)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "Certificate::getSerialNumber");
	}
	if (asn1Int->data == NULL)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "Certificate::getSerialNumber");
	}
	ret = ASN1_INTEGER_get(asn1Int);
	if (ret < 0L)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "Certificate::getSerialNumber");
	}
	return ret;
}

BigInteger Certificate::getSerialNumberBigInt() throw (CertificationException)
{
	ASN1_INTEGER *asn1Int;
	BigInteger ret;
	if (this->cert == NULL)
	{
		throw CertificationException(CertificationException::INVALID_CERTIFICATE, "Certificate::getSerialNumberBytes");
	}
	/* Here, we have a problem!!! the return value -1 can be error and a valid value. */
	asn1Int = X509_get_serialNumber(this->cert);
	if (asn1Int == NULL)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "Certificate::getSerialNumberBytes");
	}
	if (asn1Int->data == NULL)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "Certificate::getSerialNumberBytes");
	}
	ret = BigInteger(asn1Int);
	return ret;
}

MessageDigest::Algorithm Certificate::getMessageDigestAlgorithm()
		throw (MessageDigestException)
{
	MessageDigest::Algorithm ret;
	ret = MessageDigest::getMessageDigest(OBJ_obj2nid(this->cert->sig_alg->algorithm));
	return ret;
}

PublicKey* Certificate::getPublicKey() throw (CertificationException, AsymmetricKeyException)
{
	EVP_PKEY *key;
	PublicKey *ret;
	if (this->cert == NULL)
	{
		throw CertificationException(CertificationException::INVALID_CERTIFICATE, "Certificate::getPublicKey");
	}
	key = X509_get_pubkey(this->cert);
	if (key == NULL)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "Certificate::getPublicKey");
	}
	try
	{
		ret = new PublicKey(key);
	}
	catch (...)
	{
		EVP_PKEY_free(key);
		throw;
	}
	return ret;
}

ByteArray Certificate::getPublicKeyInfo()
		throw (CertificationException)
{
	ByteArray ret;
	unsigned int size;
	ASN1_BIT_STRING *temp;
	if (!this->cert->cert_info->key)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "Certificate::getPublicKeyInfo");
	}
	temp = this->cert->cert_info->key->public_key;
	ret = ByteArray(EVP_MAX_MD_SIZE);
	EVP_Digest(temp->data, temp->length, ret.getDataPointer(), &size, EVP_sha1(), NULL);
	ret = ByteArray(ret.getDataPointer(), size);
	return ret;
}

long Certificate::getVersion() throw (CertificationException)
{
	long ret;
	/* Here, we have a problem!!! the return value 0 can be error and a valid value. */
	if (this->cert == NULL)
	{
		throw CertificationException(CertificationException::INVALID_CERTIFICATE, "Certificate::getVersion");
	}
	ret = X509_get_version(this->cert);
	if (ret < 0 || ret > 2)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "Certificate::getVersion");
	}
	return ret;
}

DateTime Certificate::getNotBefore()
{
	ASN1_TIME *asn1Time;
	asn1Time = X509_get_notBefore(this->cert);
	return DateTime(asn1Time);
}

DateTime Certificate::getNotAfter()
{
	ASN1_TIME *asn1Time;
	asn1Time = X509_get_notAfter(this->cert);
	return DateTime(asn1Time);
}

RDNSequence Certificate::getIssuer()
{
	RDNSequence name;
	if (this->cert)
	{
		name = RDNSequence(X509_get_issuer_name(this->cert));
	}
	return name;
}

RDNSequence Certificate::getSubject()
{
	RDNSequence name;
	if (this->cert)
	{
		name = RDNSequence(X509_get_subject_name(this->cert));
	}
	return name;
}

std::vector<Extension*> Certificate::getExtension(Extension::Name extensionName)
{
	int next, i;
	X509_EXTENSION *ext;
	std::vector<Extension *> ret;
	Extension *oneExt;
	next = X509_get_ext_count(this->cert);
	for (i=0;i<next;i++)
	{
		ext = X509_get_ext(this->cert, i);
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
				default:
					oneExt = new Extension(ext);
					break;
			}
			ret.push_back(oneExt);
		}
	}
	return ret;
}

std::vector<Extension*> Certificate::getExtensions()
{
	int next, i;
	X509_EXTENSION *ext;
	std::vector<Extension *> ret;
	Extension *oneExt;
	next = X509_get_ext_count(this->cert);
	for (i=0;i<next;i++)
	{
		ext = X509_get_ext(this->cert, i);
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
			default:
				oneExt = new Extension(ext);
				break;
		}
		ret.push_back(oneExt);
	}
	return ret;
}

std::vector<Extension *> Certificate::getUnknownExtensions()
{
	int next, i;
	X509_EXTENSION *ext;
	std::vector<Extension *> ret;
	Extension *oneExt;
	next = X509_get_ext_count(this->cert);
	for (i=0;i<next;i++)
	{
		ext = X509_get_ext(this->cert, i);
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

ByteArray Certificate::getFingerPrint(MessageDigest::Algorithm algorithm) const
		throw (CertificationException, EncodeException, MessageDigestException)
{
	ByteArray ret, derEncoded;
	MessageDigest messageDigest;
	derEncoded = this->getDerEncoded();
	messageDigest.init(algorithm);
	ret = messageDigest.doFinal(derEncoded);
	return ret;
}

bool Certificate::verify(PublicKey &publicKey)
{
	int ok;
	ok = X509_verify(this->cert, publicKey.getEvpPkey());
	return (ok == 1);
}

X509* Certificate::getX509() const
{
	return this->cert;
}

CertificateRequest Certificate::getNewCertificateRequest(PrivateKey &privateKey, MessageDigest::Algorithm algorithm)
	throw (CertificationException)
{
	X509_REQ* req = NULL;
	req = X509_to_X509_REQ(this->cert, privateKey.getEvpPkey(), MessageDigest::getMessageDigest(algorithm));
	if (!req)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "Certificate::getNewCertificateRequest");
	}
	return CertificateRequest(req);
}

Certificate& Certificate::operator =(const Certificate& value)
{
	if (this->cert)
	{
		X509_free(this->cert);
	}
    this->cert = X509_dup(value.getX509());
    return (*this);
}

bool Certificate::operator ==(const Certificate& value)
{
	return X509_cmp(this->cert, value.getX509()) == 0;
}

bool Certificate::operator !=(const Certificate& value)
{
	return !this->operator==(value);
}
