#include <libcryptosec/PublicKey.h>

PublicKey::PublicKey(EVP_PKEY *key) throw (AsymmetricKeyException) : AsymmetricKey(key)
{
	if (key == NULL)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_ASYMMETRIC_KEY, "AsymmetricKey::AsymmetricKey");
	}
	this->key = key;
	try
	{
		this->getAlgorithm();
	}
	catch (...)
	{
		this->key = NULL;
		throw;
	}
	//TODO: testar se é mesmo uma chave publica
}

PublicKey::PublicKey(ByteArray &derEncoded)
		throw (EncodeException) : AsymmetricKey(NULL)
{
	/* DER format support only RSA, DSA and EC. DH isn't supported */
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "PublicKey::PublicKey");
	}
	if ((unsigned int)(BIO_write(buffer, derEncoded.getDataPointer(), derEncoded.size())) != derEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "PublicKey::PublicKey");
	}
	this->key = d2i_PUBKEY_bio(buffer, NULL); /* TODO: will the second parameter work fine ? */
	if (this->key == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_DECODE, "PublicKey::PublicKey");
	}
	BIO_free(buffer);
}

PublicKey::PublicKey(std::string &pemEncoded)
		throw (EncodeException) : AsymmetricKey(NULL)
{
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "PublicKey::PublicKey");
	}
	if ((unsigned int)(BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size())) != pemEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "PublicKey::PublicKey");
	}
	this->key = PEM_read_bio_PUBKEY(buffer, NULL, NULL, NULL);
	if (this->key == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_DECODE, "PublicKey::PublicKey");
	}
	BIO_free(buffer);
}

PublicKey::~PublicKey()
{
	/* super class is going to destroy the allocated objects */
}

std::string PublicKey::getPemEncoded()
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
		throw EncodeException(EncodeException::BUFFER_CREATING, "PublicKey::getPemEncoded");
	}
	wrote = PEM_write_bio_PUBKEY(buffer, this->key);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_ENCODE, "PublicKey::getPemEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "PublicKey::getPemEncoded");
	}
	retTemp = new ByteArray(data, ndata);
	ret = retTemp->toString();
	delete retTemp;
	BIO_free(buffer);
	return ret;
}

ByteArray PublicKey::getDerEncoded()
		throw (EncodeException)
{
	BIO *buffer;
	int ndata, wrote;
	ByteArray ret;
	unsigned char *data;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "PublicKey::getDerEncoded");
	}
	wrote = i2d_PUBKEY_bio(buffer, this->key);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_ENCODE, "PublicKey::getDerEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "PublicKey::getDerEncoded");
	}
	ret = ByteArray(data, ndata);
	BIO_free(buffer);
	return ret;
}

ByteArray PublicKey::getKeyIdentifier() throw (EncodeException)
{
	ByteArray ret;
	unsigned int size;
	X509_PUBKEY *pubkey = NULL;
	 const unsigned char* pubkeyData = NULL;
	 int pubkeyDataLength;

	
	if(X509_PUBKEY_set(&pubkey, this->key) == 0)
	{
		throw EncodeException(EncodeException::UNKNOWN, "PublicKey::getKeyIdentifier");
	}
			
	ret = ByteArray(EVP_MAX_MD_SIZE);

	X509_PUBKEY_get0_param(NULL, &pubkeyData, &pubkeyDataLength, NULL, pubkey); //martin: obtem X509_PUBKEY->public_key->data e X509_PUBKEY->public_key->length
	EVP_Digest(pubkeyData, pubkeyDataLength, ret.getDataPointer(), &size, EVP_sha1(), NULL); //martin: testar! faz o mesmo da linha abaixo comentada

	//EVP_Digest(pubkey->public_key->data, pubkey->public_key->length, ret.getDataPointer(), &size, EVP_sha1(), NULL);

	ret = ByteArray(ret.getDataPointer(), size);

	X509_PUBKEY_free(pubkey);
	
	return ret;
	
	//return ByteArray(digest, digestLen);

	/*	ByteArray der = this->getDerEncoded();
	MessageDigest md(MessageDigest::SHA1);
	
	MessageDigest::loadMessageDigestAlgorithms();
	
	return md.doFinal(der);*/
}
