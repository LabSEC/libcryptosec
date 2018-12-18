#include <libcryptosec/certificate/CertificateRequest.h>

CertificateRequest::CertificateRequest()
{
	this->req = X509_REQ_new();
}

CertificateRequest::CertificateRequest(X509_REQ *req)
{
	this->req = req;
}

CertificateRequest::CertificateRequest(std::string &pemEncoded)
		throw (EncodeException)
{
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateRequest::Certificate");
	}
	if ((unsigned int)(BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size())) != pemEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "CertificateRequest::Certificate");
	}
	this->req = PEM_read_bio_X509_REQ(buffer, NULL, NULL, NULL);
	if (this->req == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_DECODE, "CertificateRequest::Certificate");
	}
	BIO_free(buffer);
}

CertificateRequest::CertificateRequest(ByteArray &derEncoded)
		throw (EncodeException)
{
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateRequest::Certificate");
	}
	if ((unsigned int)(BIO_write(buffer, derEncoded.getDataPointer(), derEncoded.size())) != derEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "CertificateRequest::Certificate");
	}
	this->req = d2i_X509_REQ_bio(buffer, NULL); /* TODO: will the second parameter work fine ? */
	if (this->req == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_DECODE, "CertificateRequest::Certificate");
	}
	BIO_free(buffer);
}

CertificateRequest::CertificateRequest(const CertificateRequest& req)
{
	this->req = X509_REQ_dup(req.getX509Req());
}

CertificateRequest::~CertificateRequest()
{
	X509_REQ_free(this->req);
}

std::string CertificateRequest::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string CertificateRequest::getXmlEncoded(std::string tab)
{
	std::string ret, string;
	unsigned int i;
	RDNSequence subject;
	std::vector<Extension *> extensions;
	ByteArray publicKeyInfo;
	char temp[15];
	long value;

	ret = tab + "<certificateRequest>\n";

		value = this->getVersion();
		sprintf(temp, "%d", (int)value);
		string = temp;
		ret += tab + "\t<version>" + string + "</version>\n";

		ret += tab + "\t<subject>\n";
		subject = this->getSubject();
		ret += subject.getXmlEncoded(tab + "\t\t");
		ret += tab + "\t</subject>\n";

		try
		{
			publicKeyInfo = this->getPublicKeyInfo();
			ret += tab + "\t<publicKeyInfo>\n";
			ret += tab + "\t\t" + Base64::encode(publicKeyInfo) + "\n";
			ret += tab + "\t</publicKeyInfo>\n";
		}
		catch (...)
		{
		}

		ret += tab + "\t<extensions>\n";
		extensions = this->getExtensions();
		for (i=0;i<extensions.size();i++)
		{
			ret += extensions.at(i)->getXmlEncoded(tab + "\t\t");
			delete extensions.at(i);
		}
		ret += tab + "\t</extensions>\n";

	ret += tab + "</certificateRequest>\n";

	return ret;
}

std::string CertificateRequest::toXml(std::string tab)
{
	std::string ret, string;
	unsigned int i;
	RDNSequence subject;
	std::vector<Extension *> extensions;
	ByteArray publicKeyInfo;
	char temp[15];
	long value;

	ret = tab + "<certificateRequest>\n";

		value = this->getVersion();
		sprintf(temp, "%d", (int)value);
		string = temp;
		ret += tab + "\t<version>" + string + "</version>\n";

		ret += tab + "\t<subject>\n";
		subject = this->getSubject();
		ret += subject.getXmlEncoded(tab + "\t\t");
		ret += tab + "\t</subject>\n";

		try
		{
			publicKeyInfo = this->getPublicKeyInfo();
			ret += tab + "\t<publicKeyInfo>\n";
			ret += tab + "\t\t" + Base64::encode(publicKeyInfo) + "\n";
			ret += tab + "\t</publicKeyInfo>\n";
		}
		catch (...)
		{
		}

		ret += tab + "\t<extensions>\n";
		extensions = this->getExtensions();
		for (i=0;i<extensions.size();i++)
		{
			ret += extensions.at(i)->toXml(tab + "\t\t");
			delete extensions.at(i);
		}
		ret += tab + "\t</extensions>\n";

	ret += tab + "</certificateRequest>\n";

	return ret;
}

std::string CertificateRequest::getPemEncoded()
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
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateRequest::getPemEncoded");
	}
	wrote = PEM_write_bio_X509_REQ(buffer, this->req);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_ENCODE, "CertificateRequest::getPemEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "CertificateRequest::getPemEncoded");
	}
	retTemp = new ByteArray(data, ndata);
	ret = retTemp->toString();
	delete retTemp;
	BIO_free(buffer);
	return ret;
}

ByteArray CertificateRequest::getDerEncoded() const
		throw (EncodeException)
{
	BIO *buffer;
	int ndata, wrote;
	ByteArray ret;
	unsigned char *data;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "CertificateRequest::getDerEncoded");
	}
	wrote = i2d_X509_REQ_bio(buffer, this->req);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_ENCODE, "CertificateRequest::getDerEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "CertificateRequest::getDerEncoded");
	}
	ret = ByteArray(data, ndata);
	BIO_free(buffer);
	return ret;
}

void CertificateRequest::setVersion(long version)
{
	X509_REQ_set_version(this->req, version);
}

long CertificateRequest::getVersion()
{
	return X509_REQ_get_version(this->req);
}

MessageDigest::Algorithm CertificateRequest::getMessageDigestAlgorithm()
		throw (MessageDigestException)
{
	MessageDigest::Algorithm ret;
	ret = MessageDigest::getMessageDigest(OBJ_obj2nid(this->req->sig_alg->algorithm));
	return ret;
}

void CertificateRequest::setPublicKey(PublicKey &publicKey)
{
	X509_REQ_set_pubkey(this->req, publicKey.getEvpPkey());
}

PublicKey* CertificateRequest::getPublicKey()
		throw (CertificationException, AsymmetricKeyException)
{
	EVP_PKEY *key;
	PublicKey *ret;
	key = X509_REQ_get_pubkey(this->req);
	if (key == NULL)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateRequest::getPublicKey");
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

ByteArray CertificateRequest::getPublicKeyInfo()
		throw (CertificationException)
{
	ByteArray ret;
	unsigned int size;
	ASN1_BIT_STRING *temp;
	if (this->req->req_info->pubkey->public_key == NULL)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificateBuilder::getPublicKeyInfo");
	}
	temp = this->req->req_info->pubkey->public_key;
	ret = ByteArray(EVP_MAX_MD_SIZE);
	EVP_Digest(temp->data, temp->length, ret.getDataPointer(), &size, EVP_sha1(), NULL);
	ret = ByteArray(ret.getDataPointer(), size);
	return ret;
}

void CertificateRequest::setSubject(RDNSequence &name)
{
	X509_NAME *subject;
	subject = name.getX509Name();
	X509_REQ_set_subject_name(this->req, subject);
	X509_NAME_free(subject);
}

RDNSequence CertificateRequest::getSubject()
{
	RDNSequence ret;
	if (this->req)
	{
		ret = RDNSequence(X509_REQ_get_subject_name(this->req));
	}
	return ret;
}

void CertificateRequest::addExtension(Extension &extension)
{
	X509_EXTENSION *ext;
	STACK_OF(X509_EXTENSION) *extensions;
	int pos;
	extensions = X509_REQ_get_extensions(this->req);
	if (!extensions)
	{
		extensions = sk_X509_EXTENSION_new_null();
	}
	else
	{
		pos = X509_REQ_get_attr_by_NID(this->req, NID_ext_req, -1);
		if (pos >= 0)
		{
			X509_REQ_delete_attr(this->req, pos);
		}
	}
	ext = extension.getX509Extension();
	sk_X509_EXTENSION_push(extensions, ext);
	X509_REQ_add_extensions(this->req, extensions);
	sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
}

void CertificateRequest::addExtensions(std::vector<Extension *> &extensions)
{
	X509_EXTENSION *ext;
	STACK_OF(X509_EXTENSION) *extensionsStack;
	unsigned int i;
	if (extensions.size() > 0)
	{
		extensionsStack = sk_X509_EXTENSION_new_null();
		for (i=0;i<extensions.size();i++)
		{
			ext = extensions.at(i)->getX509Extension();
			sk_X509_EXTENSION_push(extensionsStack, ext);
		}
		X509_REQ_add_extensions(this->req, extensionsStack);
		sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free);
	}
}

void CertificateRequest::replaceExtension(Extension &extension)
		throw (CertificationException)
{
	int position;
	X509_EXTENSION *ext = extension.getX509Extension();
	STACK_OF(X509_EXTENSION)* extensionsStack = NULL;

	extensionsStack = X509_REQ_get_extensions(this->req); //pega uma copia da pilha de extencoes da req

	if(extensionsStack == NULL) //pilha nao instanciada
	{
		extensionsStack = sk_X509_EXTENSION_new_null();
		sk_X509_EXTENSION_push(extensionsStack, ext);
	}
	else //pilha instanciada previamente
	{
		position =  X509v3_get_ext_by_OBJ(extensionsStack, extension.getObjectIdentifier().getObjectIdentifier(), -1);
		if (position >= 0)
		{
			if(sk_X509_EXTENSION_insert(extensionsStack, ext, position) == 0)
			{
				throw CertificationException(CertificationException::ADDING_EXTENSION, "CertificateRequest::replaceExtension");
			}

			ext = sk_X509_EXTENSION_delete(extensionsStack, position + 1);
			X509_EXTENSION_free(ext);
		}
		else //pilha vazia ou sem a extensao previamente adicionada
		{
			if(sk_X509_EXTENSION_insert(extensionsStack, ext, -1) == 0)
			{
				throw CertificationException(CertificationException::ADDING_EXTENSION, "CertificateRequest::replaceExtension");
			}
		}

		position = X509_REQ_get_attr_by_NID(this->req, NID_ext_req, -1); //apaga pilha antiga da req
		if (position >= 0)
		{
			X509_REQ_delete_attr(this->req, position);
		}
	}

	//adiciona nova pilha a req
	X509_REQ_add_extensions(this->req, extensionsStack);
	sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free); //apaga copia local da pilha
}

std::vector<Extension *> CertificateRequest::removeExtension(Extension::Name extensionName) throw (CertificationException)
{
	int i, position;
	X509_EXTENSION *ext;
	std::vector<Extension *> ret;
	Extension *oneExt;
	STACK_OF(X509_EXTENSION)* extensionsStack = NULL;
	bool stackChange = false;

	extensionsStack = X509_REQ_get_extensions(this->req); //pega uma copia da pilha de extencoes da req

	i = 0;
	while(i < sk_X509_EXTENSION_num(extensionsStack))
	{
		ext = sk_X509_EXTENSION_value(extensionsStack, i);

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
			ext = sk_X509_EXTENSION_delete(extensionsStack, i);
			X509_EXTENSION_free(ext);
			//nao incrementa i pois um elemento do array foi removido
			stackChange = true;
		}
		else
		{
			i++;
		}
	}

	if(stackChange)
	{
		position = X509_REQ_get_attr_by_NID(this->req, NID_ext_req, -1); //apaga pilha antiga da req
		if (position >= 0)
		{
			X509_REQ_delete_attr(this->req, position);

			//adiciona nova pilha a req
			X509_REQ_add_extensions(this->req, extensionsStack);
			sk_X509_EXTENSION_pop_free(extensionsStack, X509_EXTENSION_free); //apaga copia local da pilha
		}
	}

	return ret;
}


std::vector<Extension *> CertificateRequest::removeExtension(ObjectIdentifier extOID) throw (CertificationException)
{
	ASN1_OBJECT* obj = extOID.getObjectIdentifier(); //nao desalocar!
	int nid = OBJ_obj2nid(obj);
	return this->removeExtension(Extension::getName(nid));
}

std::vector<Extension *> CertificateRequest::getExtension(Extension::Name extensionName)
{
	int i;
	X509_EXTENSION *ext;
	STACK_OF(X509_EXTENSION) *extensions;
	std::vector<Extension *> ret;
	Extension *oneExt;
	extensions = X509_REQ_get_extensions(this->req);
	for (i=0;i<sk_X509_EXTENSION_num(extensions);i++)
	{
		ext = sk_X509_EXTENSION_value(extensions, i);
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

std::vector<Extension*> CertificateRequest::getExtensions()
{
	int i;
	X509_EXTENSION *ext;
	std::vector<Extension *> ret;
	STACK_OF(X509_EXTENSION) *extensions;
	Extension *oneExt;
	extensions = X509_REQ_get_extensions(this->req);
	for (i=0;i<sk_X509_EXTENSION_num(extensions);i++)
	{
		ext = sk_X509_EXTENSION_value(extensions, i);
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

std::vector<Extension *> CertificateRequest::getUnknownExtensions()
{
	int i;
	X509_EXTENSION *ext;
	STACK_OF(X509_EXTENSION) *extensions;
	std::vector<Extension *> ret;
	Extension *oneExt;

	extensions = X509_REQ_get_extensions(this->req);
	for (i=0;i<sk_X509_EXTENSION_num(extensions);i++)
	{
		ext = sk_X509_EXTENSION_value(extensions, i);
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

ByteArray CertificateRequest::getFingerPrint(MessageDigest::Algorithm algorithm) const
		throw (CertificationException, EncodeException, MessageDigestException)
{
	ByteArray ret, derEncoded;
	MessageDigest messageDigest;
	derEncoded = this->getDerEncoded();
	messageDigest.init(algorithm);
	ret = messageDigest.doFinal(derEncoded);
	return ret;
}

void CertificateRequest::sign(PrivateKey &privateKey, MessageDigest::Algorithm messageDigestAlgorithm)
		throw (CertificationException)
{
	int rc;
	PublicKey *pub;
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

	rc = X509_REQ_sign(this->req, privateKey.getEvpPkey(), MessageDigest::getMessageDigest(messageDigestAlgorithm));
	if (!rc)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CertificateRequest::sign");
	}
}

bool CertificateRequest::verify()
{
	int rc;
	PublicKey *pub;
	pub = this->getPublicKey();
	rc = X509_REQ_verify(this->req, pub->getEvpPkey());
	delete pub;
	return (rc==1?true:false);
}

bool CertificateRequest::isSigned() const throw()
{
	return ASN1_STRING_data(this->req->signature) != NULL;
}


X509_REQ* CertificateRequest::getX509Req() const
{
	return this->req;
}

CertificateRequest& CertificateRequest::operator =(const CertificateRequest& value)
{
	if (this->req)
	{
		X509_REQ_free(this->req);
	}
    this->req = X509_REQ_dup(value.getX509Req());
    return (*this);
}
