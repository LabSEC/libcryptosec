#include <libcryptosec/PrivateKey.h>

PrivateKey::PrivateKey(EVP_PKEY *key) throw (AsymmetricKeyException) : AsymmetricKey(key)
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
	//TODO: testar se é mesmo uma chave privada
}

PrivateKey::PrivateKey(ByteArray &derEncoded)
		throw (EncodeException) : AsymmetricKey(NULL)
{
	/* DER format support only RSA, DSA and EC. DH isn't supported */
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "PrivateKey::PrivateKey");
	}
	if ((unsigned int)(BIO_write(buffer, derEncoded.getDataPointer(), derEncoded.size())) != derEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "PrivateKey::PrivateKey");
	}
	this->key = d2i_PrivateKey_bio(buffer, NULL); /* TODO: will the second parameter work fine ? */
	if (this->key == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_DECODE, "PrivateKey::PrivateKey");
	}
	BIO_free(buffer);
}

PrivateKey::PrivateKey(std::string &pemEncoded)
		throw (EncodeException) : AsymmetricKey(NULL)
{
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "PrivateKey::PrivateKey");
	}
	if ((unsigned int)(BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size())) != pemEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "PrivateKey::PrivateKey");
	}
	this->key = PEM_read_bio_PrivateKey(buffer, NULL, NULL, NULL);
	if (this->key == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_DECODE, "PrivateKey::PrivateKey");
	}
	BIO_free(buffer);
}

PrivateKey::PrivateKey(std::string &pemEncoded, ByteArray &passphrase)
		throw (EncodeException) : AsymmetricKey(NULL)
{ 
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "PrivateKey::PrivateKey");
	}
	if ((unsigned int)(BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size())) != pemEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "PrivateKey::PrivateKey");
	}
	this->key = PEM_read_bio_PrivateKey(buffer, NULL, PrivateKey::passphraseCallBack, (void *)&passphrase);
	if (this->key == NULL)
	{
		BIO_free(buffer);
		/* TODO: how to know if is the passphrase wrong ??? */
		throw EncodeException(EncodeException::PEM_DECODE, "PrivateKey::PrivateKey");
	}
	BIO_free(buffer);
}

PrivateKey::~PrivateKey()
{
}

std::string PrivateKey::getPemEncoded()
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
		throw EncodeException(EncodeException::BUFFER_CREATING, "PrivateKey::getPemEncoded");
	}
	wrote = PEM_write_bio_PrivateKey(buffer, this->key, NULL, NULL, 0, NULL, NULL);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_ENCODE, "PrivateKey::getPemEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "PrivateKey::getPemEncoded");
	}
	retTemp = new ByteArray(data, ndata);
	ret = retTemp->toString();
	delete retTemp;
	BIO_free(buffer);
	return ret;
}

std::string PrivateKey::getPemEncoded(SymmetricKey &passphrase, SymmetricCipher::OperationMode mode)
	throw (SymmetricCipherException, EncodeException)
{
	BIO *buffer;
	const EVP_CIPHER *cipher;
	int ndata, wrote;
	std::string ret;
	ByteArray *retTemp;
	unsigned char *data;
	ByteArray passphraseData;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "PrivateKey::getPemEncoded");
	}
	try
	{
		cipher = SymmetricCipher::getCipher(passphrase.getAlgorithm(), mode);
	}
	catch (...)
	{
		BIO_free(buffer);
		throw;
	}
	passphraseData = passphrase.getEncoded();
	wrote = PEM_write_bio_PrivateKey(buffer, this->key, cipher, NULL, 0, PrivateKey::passphraseCallBack, (void *)&passphraseData);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_ENCODE, "PrivateKey::getPemEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "PrivateKey::getPemEncoded");
	}
	retTemp = new ByteArray(data, ndata);
	ret = retTemp->toString();
	delete retTemp;
	BIO_free(buffer);
	return ret;
}

ByteArray PrivateKey::getDerEncoded()
		throw (EncodeException)
{
	BIO *buffer;
	int ndata, wrote;
	ByteArray ret;
	unsigned char *data;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "PrivateKey::getDerEncoded");
	}
	wrote = i2d_PrivateKey_bio(buffer, this->key);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_ENCODE, "PrivateKey::getDerEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "PrivateKey::getDerEncoded");
	}
	ret = ByteArray(data, ndata);
	BIO_free(buffer);
	return ret;
}

bool PrivateKey::operator==(PrivateKey& priv) throw()
{
	return EVP_PKEY_cmp(this->getEvpPkey(), priv.getEvpPkey()) == 0;
}

int PrivateKey::passphraseCallBack(char *buf, int size, int rwflag, void *u)
{
    ByteArray* passphrase = (ByteArray*) u;
    int length = passphrase->size();
    if (length > 0)
    {
        if (length > size)
        {
            length = size;
        }
        memcpy(buf, passphrase->getDataPointer(), length);
    }
    return length;
}
