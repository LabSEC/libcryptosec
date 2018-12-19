#include <libcryptosec/certificate/CertificateBuilder.h>

CertificateBuilder::CertificateBuilder()
{
	DateTime dateTime;
	this->cert = X509_new();
	this->setNotBefore(dateTime);
	this->setNotAfter(dateTime);
	this->setIncludeEcdsaParameters(false);
}

CertificateBuilder::CertificateBuilder(std::string pemEncoded)
		throw (EncodeException)
{
	this->setIncludeEcdsaParameters(false);
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateBuilder::CertificateBuilder");
	}
	if ((unsigned int)(BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size())) != pemEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "CertificateBuilder::CertificateBuilder");
	}
	this->cert = PEM_read_bio_X509(buffer, NULL, NULL, NULL);
	if (this->cert == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_DECODE, "CertificateBuilder::CertificateBuilder");
	}
	BIO_free(buffer);
}

CertificateBuilder::CertificateBuilder(ByteArray &derEncoded)
	throw (EncodeException)
{
	this->setIncludeEcdsaParameters(false);
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateBuilder::CertificateBuilder");
	}
	if ((unsigned int)(BIO_write(buffer, derEncoded.getDataPointer(), derEncoded.size())) != derEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "CertificateBuilder::CertificateBuilder");
	}
	this->cert = d2i_X509_bio(buffer, NULL); /* TODO: will the second parameter work fine ? */
	if (this->cert == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_DECODE, "CertificateBuilder::CertificateBuilder");
	}
	BIO_free(buffer);
}

CertificateBuilder::CertificateBuilder(CertificateRequest &request)
{
	this->setIncludeEcdsaParameters(false);
	RDNSequence subject;
	PublicKey *publicKey = NULL;
	std::vector<Extension *> extensions;
	unsigned int i;
	DateTime dateTime;

	this->cert = X509_new();
	this->setNotBefore(dateTime);
	this->setNotAfter(dateTime);

	this->setSubject(request.getX509Req());
	try
	{
		publicKey = request.getPublicKey();
		this->setPublicKey(*publicKey);
	}
	catch (CertificationException &ex)
	{
	}
	try
	{
		extensions = request.getExtensions();
		for (i=0;i<extensions.size();i++)
		{
			this->addExtension(*extensions.at(i));
		}
	}
	catch (CertificationException &ex)
	{
	}
	if (publicKey)
	{
		delete publicKey;
	}
//	for (i=0;i<extensions.size();i++) //todo Para algumas extensoes como AuthorityInformationAccess, em alguns casos
//	{										 o delete nao esta funcionando adequadamente
//		delete extensions.at(i);
//	}
}

CertificateBuilder::CertificateBuilder(const CertificateBuilder& cert)
{
	this->cert = X509_dup(cert.getX509());
	this->setIncludeEcdsaParameters(cert.isIncludeEcdsaParameters());
}

CertificateBuilder::~CertificateBuilder()
{
	X509_free(this->cert);
	this->cert = NULL;
}

std::string CertificateBuilder::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string CertificateBuilder::getXmlEncoded(std::string tab)
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
//		string = OBJ_nid2ln(OBJ_obj2nid(this->cert->sig_alg->algorithm));
//		ret += "\t\t<signature>" + string + "</signature>\n";

		//verifica se o issuer foi definido
		if(sk_X509_NAME_ENTRY_num(X509_get_issuer_name(this->cert)->entries) > 0)
		{
			ret += "\t\t<issuer>\n";
				try
				{
					ret += (this->getIssuer()).getXmlEncoded("\t\t\t");
				}
				catch (...)
				{
				}
			ret += "\t\t</issuer>\n";
		}

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
			if (this->cert->cert_info->key)
			{
				string = OBJ_nid2ln(OBJ_obj2nid(this->cert->cert_info->key->algor->algorithm));
				ret += "\t\t\t<algorithm>" + string + "</algorithm>\n";
				data = ByteArray(this->cert->cert_info->key->public_key->data, this->cert->cert_info->key->public_key->length);
				string = Base64::encode(data);
				ret += "\t\t\t<subjectPublicKey>" + string + "</subjectPublicKey>\n";
			}
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

//	ret += "\t<signatureAlgorithm>\n";
//		string = OBJ_nid2ln(OBJ_obj2nid(this->cert->sig_alg->algorithm));
//		ret += "\t\t<algorithm>" + string + "</algorithm>\n";
//	ret += "\t</signatureAlgorithm>\n";
//
//	data = ByteArray(this->cert->signature->data, this->cert->signature->length);
//	string = Base64::encode(data);
//	ret += "\t<signatureValue>" + string + "</signatureValue>\n";

	ret += "</certificate>\n";
	return ret;
}

std::string CertificateBuilder::toXml(std::string tab)
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
//		string = OBJ_nid2ln(OBJ_obj2nid(this->cert->sig_alg->algorithm));
//		ret += "\t\t<signature>" + string + "</signature>\n";

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
			if (this->cert->cert_info->key)
			{
				string = OBJ_nid2ln(OBJ_obj2nid(this->cert->cert_info->key->algor->algorithm));
				ret += "\t\t\t<algorithm>" + string + "</algorithm>\n";
				data = ByteArray(this->cert->cert_info->key->public_key->data, this->cert->cert_info->key->public_key->length);
				string = Base64::encode(data);
				ret += "\t\t\t<subjectPublicKey>" + string + "</subjectPublicKey>\n";
			}
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

//	ret += "\t<signatureAlgorithm>\n";
//		string = OBJ_nid2ln(OBJ_obj2nid(this->cert->sig_alg->algorithm));
//		ret += "\t\t<algorithm>" + string + "</algorithm>\n";
//	ret += "\t</signatureAlgorithm>\n";
//
//	data = ByteArray(this->cert->signature->data, this->cert->signature->length);
//	string = Base64::encode(data);
//	ret += "\t<signatureValue>" + string + "</signatureValue>\n";

	ret += "</certificate>\n";
	return ret;

}

std::string CertificateBuilder::getPemEncoded() throw (EncodeException)
{
	BIO *buffer;
	int ndata, wrote;
	std::string ret;
	ByteArray *retTemp;
	unsigned char *data;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateBuilder::getPemEncoded");
	}
	wrote = PEM_write_bio_X509(buffer, this->cert);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_ENCODE, "CertificateBuilder::getPemEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "CertificateBuilder::getPemEncoded");
	}
	retTemp = new ByteArray(data, ndata);
	ret = retTemp->toString();
	delete retTemp;
	BIO_free(buffer);
	return ret;
}

ByteArray CertificateBuilder::getDerEncoded() throw (EncodeException)
{
	BIO *buffer;
	int ndata, wrote;
	ByteArray ret;
	unsigned char *data;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateBuilder::getDerEncoded");
	}
	wrote = i2d_X509_bio(buffer, this->cert);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_ENCODE, "CertificateBuilder::getDerEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "CertificateBuilder::getDerEncoded");
	}
	ret = ByteArray(data, ndata);
	BIO_free(buffer);
	return ret;
}

void CertificateBuilder::setSerialNumber(long serial)
{
	ASN1_INTEGER_set(X509_get_serialNumber(this->cert), serial);
}

void CertificateBuilder::setSerialNumber(BigInteger serial) throw(BigIntegerException)
{
	X509_set_serialNumber(this->cert, serial.getASN1Value());
}

long CertificateBuilder::getSerialNumber() throw (CertificationException)
{
	ASN1_INTEGER *asn1Int;
	long ret;
	/* Here, we have a problem!!! the return value -1 can be error and a valid value. */
	asn1Int = X509_get_serialNumber(this->cert);
	if (asn1Int == NULL)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateBuilder::getSerialNumber");
	}
	if (asn1Int->data == NULL)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::getSerialNumber");
	}
	ret = ASN1_INTEGER_get(asn1Int);
	if (ret < 0L)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::getSerialNumber");
	}
	return ret;
}

BigInteger CertificateBuilder::getSerialNumberBigInt() throw (CertificationException, BigIntegerException)
{
	ASN1_INTEGER *asn1Int;
	/* Here, we have a problem!!! the return value -1 can be error and a valid value. */
	asn1Int = X509_get_serialNumber(this->cert);
	if (asn1Int == NULL)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateBuilder::getSerialNumber");
	}
	if (asn1Int->data == NULL)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::getSerialNumber");
	}
	return BigInteger(asn1Int);
}

MessageDigest::Algorithm CertificateBuilder::getMessageDigestAlgorithm()
		throw (MessageDigestException)
{
	MessageDigest::Algorithm ret;
	ret = MessageDigest::getMessageDigest(OBJ_obj2nid(this->cert->sig_alg->algorithm));
	return ret;
}

void CertificateBuilder::setPublicKey(PublicKey &publicKey)
{
	X509_set_pubkey(this->cert, publicKey.getEvpPkey());
}

PublicKey* CertificateBuilder::getPublicKey()
		throw (CertificationException, AsymmetricKeyException)
{
	EVP_PKEY *key;
	PublicKey *ret;
	key = X509_get_pubkey(this->cert);
	if (key == NULL)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateBuilder::getPublicKey");
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

ByteArray CertificateBuilder::getPublicKeyInfo()
		throw (CertificationException)
{
	ByteArray ret;
	unsigned int size;
	ASN1_BIT_STRING *temp;
	if (!this->cert->cert_info->key)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateBuilder::getPublicKeyInfo");
	}
	temp = this->cert->cert_info->key->public_key;
	ret = ByteArray(EVP_MAX_MD_SIZE);
	EVP_Digest(temp->data, temp->length, ret.getDataPointer(), &size, EVP_sha1(), NULL);
	ret = ByteArray(ret.getDataPointer(), size);
	return ret;
}

void CertificateBuilder::setVersion(long version)
{
	X509_set_version(this->cert, version);
}

long CertificateBuilder::getVersion() throw (CertificationException)
{
	long ret;
	/* Here, we have a problem!!! the return value 0 can be error and a valid value. */
	if (this->cert == NULL)
	{
		throw CertificationException(CertificationException::INVALID_CERTIFICATE, "CertificateBuilder::getVersion");
	}
	ret = X509_get_version(this->cert);
	if (ret < 0 || ret > 2)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateBuilder::getVersion");
	}
	return ret;
}

void CertificateBuilder::setNotBefore(DateTime &dateTime)
{
	ASN1_TIME *asn1Time;
	asn1Time = dateTime.getAsn1Time();
	X509_set_notBefore(this->cert, asn1Time);
	ASN1_TIME_free(asn1Time);
}

DateTime CertificateBuilder::getNotBefore()
{
	ASN1_TIME *asn1Time;
	asn1Time = X509_get_notBefore(this->cert);
	return DateTime(asn1Time);
}

void CertificateBuilder::setNotAfter(DateTime &dateTime)
{
	ASN1_TIME *asn1Time;
	asn1Time = dateTime.getAsn1Time();
	X509_set_notAfter(this->cert, asn1Time);
	ASN1_TIME_free(asn1Time);
}

DateTime CertificateBuilder::getNotAfter()
{
	ASN1_TIME *asn1Time;
	asn1Time = X509_get_notAfter(this->cert);
	return DateTime(asn1Time);
}

void CertificateBuilder::setIssuer(RDNSequence &name)
{
	X509_NAME *issuer;
	issuer = name.getX509Name();
	X509_set_issuer_name(this->cert, issuer);
	X509_NAME_free(issuer);
}

void CertificateBuilder::setIssuer(X509* issuer)
		throw (CertificationException)
{
	int rc;
	X509_NAME *name = X509_get_subject_name(issuer);
	rc = X509_set_issuer_name(this->cert, X509_NAME_dup(name));
	if (!rc)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::setIssuer");
	}
}

RDNSequence CertificateBuilder::getIssuer()
{
	return RDNSequence(X509_get_issuer_name(this->cert));
}

void CertificateBuilder::alterSubject(RDNSequence &name)
		throw (CertificationException)
{
	X509_NAME *subject = X509_get_subject_name(this->cert);
	if(subject == NULL)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
	}
	X509_NAME *subjectName = X509_NAME_new();
	if(subjectName == NULL)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
	}
	std::vector<std::pair<ObjectIdentifier, std::string> > entries = name.getEntries();
	X509_NAME_ENTRY *newEntry;

	int addedFieldType = this->getCodification(name);

	std::string data;
	for(std::vector<std::pair<ObjectIdentifier, std::string> >::iterator entry = entries.begin(); entry != entries.end(); entry++)
	{
		data = entry->second;
		newEntry = X509_NAME_ENTRY_new();

		int position = X509_NAME_get_index_by_NID(subject, entry->first.getNid(), -1);

		if(!data.empty()) // If entry is not empty, add entry
		{
			if(position != -1)
			{
				X509_NAME_ENTRY* oldEntry = X509_NAME_get_entry(subject, position);

				int entryType = oldEntry->value->type;

				if(!X509_NAME_ENTRY_set_object(newEntry, entry->first.getObjectIdentifier()))
				{
					throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
				}

				if(!X509_NAME_ENTRY_set_data(newEntry, entryType, (unsigned char *)data.c_str(), data.length()))
				{
					throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
				}

				if(!X509_NAME_add_entry(subjectName, newEntry, -1, 0))
				{
					throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
				}

				X509_NAME_ENTRY_free(newEntry);

			}
			else
			{
				if(!X509_NAME_ENTRY_set_object(newEntry, entry->first.getObjectIdentifier()))
				{
					throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
				}
				if(!X509_NAME_ENTRY_set_data(newEntry, addedFieldType, (unsigned char *)data.c_str(), data.length()))
				{
					throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
				}
				if(!X509_NAME_add_entry(subjectName, newEntry, -1, 0))
				{
					throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
				}
				X509_NAME_ENTRY_free(newEntry);
			}
		}
	}

	int rc = X509_set_subject_name(this->cert, subjectName);
	X509_NAME_free(subjectName);

	if(!rc)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
	}

/*	ALTERSUBJECT VERSION 2.2.4
	X509_NAME *subject = X509_get_subject_name(this->cert);

	if(subject == NULL){
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::setSubject");
	}

	std::vector<std::pair<ObjectIdentifier, std::string> > entries = name.getEntries();

	int entryType = MBSTRING_ASC;
	for (int i=0; i<entries.size(); i++)
	{
		int pos = X509_NAME_get_index_by_OBJ(subject, entries.at(i).first.getObjectIdentifier(), -1);
		bool notCountry = entries.at(i).first.getNid() != NID_countryName;
		if (pos >= 0 && notCountry)
		{
			X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, pos);
			entryType = entry->value->type;
			break;
		}
	}

	for (int i=0; i<entries.size(); i++)
	{
		int nameEntryPos = X509_NAME_get_index_by_OBJ(subject, entries.at(i).first.getObjectIdentifier(), -1);
		X509_NAME_ENTRY* ne;
		std::string data = entries.at(i).second;
		if (!data.empty())
		{
			if (nameEntryPos >= 0)
			{
				ne = X509_NAME_get_entry(subject, nameEntryPos);
				int rc = X509_NAME_ENTRY_set_data(ne, ne->value->type, (unsigned char *)data.c_str(), data.length());
				if (!rc)
				{
					throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::setSubject");
				}
			}
			else
			{
				ne = X509_NAME_ENTRY_new();
				X509_NAME_ENTRY_set_object(ne, entries.at(i).first.getObjectIdentifier());
				X509_NAME_ENTRY_set_data(ne, entryType, (unsigned char *)data.c_str(), data.length());
				X509_NAME_add_entry(subject, ne, -1, 0);
				X509_NAME_ENTRY_free(ne);
			}
		}
	}
	name = RDNSequence(subject);*/
}

void CertificateBuilder::setSubject(RDNSequence &name)
{
	X509_NAME *subject;
	subject = name.getX509Name();
	X509_set_subject_name(this->cert, subject);
	X509_NAME_free(subject);
}

void CertificateBuilder::setSubject(X509_REQ* req)
		throw (CertificationException)
{
	int rc;
	X509_NAME *name = X509_REQ_get_subject_name(req);
	rc = X509_set_subject_name(this->cert, X509_NAME_dup(name));
	if (!rc)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::setSubject");
	}
}

RDNSequence CertificateBuilder::getSubject()
{
	return RDNSequence(X509_get_subject_name(this->cert));
}

void CertificateBuilder::addExtension(Extension &extension)
		throw (CertificationException)
{
	X509_EXTENSION *ext;
	int rc;
	ext = extension.getX509Extension();
	rc = X509_add_ext(this->cert, ext, -1);
	if (!rc)
	{
		throw CertificationException(CertificationException::ADDING_EXTENSION, "CertificateBuilder::addExtension");
	}
}

void CertificateBuilder::addExtensions(std::vector<Extension *> &extensions)
		throw (CertificationException)
{
	X509_EXTENSION *ext;
	int rc;
	unsigned int i;
	for (i=0;i<extensions.size();i++)
	{
		ext = extensions.at(i)->getX509Extension();
		rc = X509_add_ext(this->cert, ext, -1);
		if (!rc)
		{
			throw CertificationException(CertificationException::ADDING_EXTENSION, "CertificateBuilder::addExtension");
		}
	}
}

void CertificateBuilder::replaceExtension(Extension &extension)
		throw (CertificationException)
{
	int position;
	X509_EXTENSION *ext;
	position = X509_get_ext_by_OBJ(this->cert, extension.getObjectIdentifier().getObjectIdentifier(), -1);
	if (position >= 0)
	{
		ext = extension.getX509Extension();
		if(X509_add_ext(this->cert, ext, position) == 0)
		{
			throw CertificationException(CertificationException::ADDING_EXTENSION, "CertificateBuilder::replaceExtension");
		}

		ext = X509_delete_ext(this->cert, position + 1);
		X509_EXTENSION_free(ext);
	}
	else //a extensao nao esta presente, adiciona no topo da pilha
	{
		this->addExtension(extension);
	}
}

std::vector<Extension*> CertificateBuilder::getExtension(Extension::Name extensionName)
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

std::vector<Extension*> CertificateBuilder::getExtensions()
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

std::vector<Extension *> CertificateBuilder::getUnknownExtensions()
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

std::vector<Extension *> CertificateBuilder::removeExtension(Extension::Name extensionName) throw (CertificationException)
{
	int i;
	X509_EXTENSION *ext;
	std::vector<Extension *> ret;
	Extension *oneExt;

	i = 0;
	while(i < X509_get_ext_count(this->cert))
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
			ext = X509_delete_ext(this->cert, i);
			X509_EXTENSION_free(ext);
			//nao incrementa i pois um elemento do array foi removido
		}
		else
		{
			i++;
		}
	}
	return ret;

}

std::vector<Extension *> CertificateBuilder::removeExtension(ObjectIdentifier extOID) throw (CertificationException)
{
	int i;
	X509_EXTENSION *ext = NULL;
	std::vector<Extension *> ret;
	Extension *oneExt = NULL;
	ASN1_OBJECT* obj = NULL;

	i = 0;
	while(i < X509_get_ext_count(this->cert))
	{
		ext = X509_get_ext(this->cert, i);
		obj = X509_EXTENSION_get_object(ext);

		if (OBJ_cmp(obj, extOID.getObjectIdentifier()) == 0)
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
			ext = X509_delete_ext(this->cert, i);
			X509_EXTENSION_free(ext);
			//nao incrementa i pois um elemento do array foi removido
		}
		else
		{
			i++;
		}
	}
	return ret;
}

Certificate* CertificateBuilder::sign(PrivateKey &privateKey, MessageDigest::Algorithm messageDigestAlgorithm)
		throw (CertificationException, AsymmetricKeyException)
{
	PublicKey *pub;
	Certificate *ret;
	DateTime dateTime;
	int rc;
	pub = this->getPublicKey();
	delete pub;

	// TODO: We force Identity message digest for EdDSA to avoid changing callers which always pass digests.
	EVP_PKEY* pkey = privateKey.getEvpPkey();
	int pkeyType = EVP_PKEY_type(pkey->type);
	int nid25519 = OBJ_sn2nid("ED25519");
	int nid521 = OBJ_sn2nid("ED521");
	int nid448 = OBJ_sn2nid("ED448");
	if (pkeyType == nid25519 || pkeyType == nid521 || pkeyType == nid448) {
		messageDigestAlgorithm = MessageDigest::Identity;
	}

	rc = X509_sign(this->cert, privateKey.getEvpPkey(), MessageDigest::getMessageDigest(messageDigestAlgorithm));
	if (!rc)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::sign");
	}
	ret = new Certificate(this->cert);
	this->cert = X509_new();
	this->setNotBefore(dateTime);
	this->setNotAfter(dateTime);
	return ret;
}

X509* CertificateBuilder::getX509() const
{
	return this->cert;
}

CertificateBuilder& CertificateBuilder::operator =(const CertificateBuilder& value)
{
	if (this->cert)
	{
		X509_free(this->cert);
	}
    this->cert = X509_dup(value.getX509());
    this->setIncludeEcdsaParameters(value.isIncludeEcdsaParameters());
    return (*this);
}

bool CertificateBuilder::isIncludeEcdsaParameters() const {
	return this->includeECDSAParameters;
}

void CertificateBuilder::setIncludeEcdsaParameters(bool includeEcdsaParameters) {
	this->includeECDSAParameters = includeEcdsaParameters;
}

void CertificateBuilder::includeEcdsaParameters() {
	PublicKey* publicKey = this->getPublicKey();

	if(publicKey) {
		if(publicKey->getAlgorithm() == AsymmetricKey::ECDSA && this->isIncludeEcdsaParameters()) {
			EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(publicKey->getEvpPkey());
			EC_KEY_set_asn1_flag(ec_key, 0);
		}

		this->setPublicKey(*publicKey);
		delete publicKey;
	}
}

int CertificateBuilder::getCodification(RDNSequence& name){
	int entryType = MBSTRING_ASC;
	X509_NAME *subject = X509_get_subject_name(this->cert);
	if(subject == NULL)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateBuilder::alterSubject");
	}

	std::vector<std::pair<ObjectIdentifier, std::string> > entries = name.getEntries();

	for(std::vector<std::pair<ObjectIdentifier, std::string> >::iterator entry = entries.begin(); entry != entries.end(); entry++)
	{
		int position = X509_NAME_get_index_by_NID(subject, entry->first.getNid(), -1);
		if(position != -1 && entry->first.getNid() != NID_countryName)
		{
			X509_NAME_ENTRY* oldEntry = X509_NAME_get_entry(subject, position);
			entryType = oldEntry->value->type;
			if(entryType != MBSTRING_FLAG) {
				return entryType;
			}
		}
	}

	return entryType;
}
