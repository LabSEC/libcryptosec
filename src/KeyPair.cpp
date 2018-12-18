#include <libcryptosec/KeyPair.h>

KeyPair::KeyPair()
{
}

//TODO Este construtor deve é obsoleto. Devem ser usados os construtores das classes especializadas RSAKeyPair, DSAKeyPair e ECDSAKeyPair
KeyPair::KeyPair(AsymmetricKey::Algorithm algorithm, int length)
		throw (AsymmetricKeyException)
{
	RSA *rsa;
	DSA *dsa;
	EC_KEY *eckey;
	this->key = NULL;
	this->engine = NULL;
	rsa = NULL;
	dsa = NULL;
	eckey = NULL;
	switch (algorithm)
	{
		case AsymmetricKey::RSA:
			rsa = RSA_generate_key(length, RSA_F4, NULL, NULL);
			if (!rsa)
			{
				break;
			}
			this->key = EVP_PKEY_new();
			EVP_PKEY_assign_RSA(this->key, rsa);
			break;
		case AsymmetricKey::DSA:
			dsa = DSA_generate_parameters(length, NULL, 0, NULL, NULL, NULL, NULL);
			if (!dsa)
			{
				break;
			}
			DSA_generate_key(dsa);
			if (!dsa)
			{
				break;
			}
			this->key = EVP_PKEY_new();
			EVP_PKEY_assign_DSA(this->key, dsa);
			break;
		case AsymmetricKey::ECDSA:
			break;
		case AsymmetricKey::EdDSA:
			break;
	}
	if (!this->key)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR, "KeyPair::KeyPair");
	}
}

KeyPair::KeyPair(Engine *engine, std::string keyId)
		throw (EngineException)
{
	ENGINE *eng;
	eng = engine->getEngine();
	if (!ENGINE_init(eng))
	{
		throw EngineException(EngineException::INIT_FAILED, "KeyPair::KeyPair", true);
	}
	// TODO: rever essa questão do User Interface UI_OpenSSL();
//	this->key = ENGINE_load_public_key(eng, keyId.c_str(), UI_OpenSSL(), NULL);
	this->key = ENGINE_load_private_key(eng, keyId.c_str(), NULL, NULL);
	ENGINE_finish(eng);
	if (!this->key)
	{
		throw EngineException(EngineException::KEY_NOT_FOUND, "KeyPair::KeyPair", true);
	}
	this->engine = engine->getEngine();
	this->keyId = keyId;
	ENGINE_up_ref(this->engine);
}

KeyPair::KeyPair(std::string pemEncoded, ByteArray passphrase)
		throw (EncodeException)
{
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "KeyPair::KeyPair");
	}
	if ((unsigned int)(BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size())) != pemEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "KeyPair::KeyPair");
	}
	this->key = PEM_read_bio_PrivateKey(buffer, NULL, KeyPair::passphraseCallBack, (void *)&passphrase);
	if (this->key == NULL)
	{
		BIO_free(buffer);
		/* TODO: how to know if is the passphrase wrong ??? */
		throw EncodeException(EncodeException::PEM_DECODE, "KeyPair::KeyPair");
	}
	BIO_free(buffer);
	this->engine = NULL;
}

KeyPair::KeyPair(std::string pemEncoded)
		throw (EncodeException)
{
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "KeyPair::KeyPair");
	}
	if ((unsigned int)(BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size())) != pemEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "KeyPair::KeyPair");
	}
	this->key = PEM_read_bio_PrivateKey(buffer, NULL, NULL, NULL);
	if (this->key == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_DECODE, "KeyPair::KeyPair");
	}
	BIO_free(buffer);
	this->engine = NULL;
}

KeyPair::KeyPair(ByteArray derEncoded)
		throw (EncodeException)
{
	/* DER format support only RSA, DSA and EC. DH isn't supported */
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "KeyPair::KeyPair");
	}
	if ((unsigned int)(BIO_write(buffer, derEncoded.getDataPointer(), derEncoded.size())) != derEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "KeyPair::KeyPair");
	}
	this->key = d2i_PrivateKey_bio(buffer, NULL); /* TODO: will the second parameter work fine ? */
	if (this->key == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_DECODE, "KeyPair::KeyPair");
	}
	BIO_free(buffer);
	this->engine = NULL;
}

KeyPair::KeyPair(const KeyPair &keyPair)
{
	this->key = keyPair.getEvpPkey();
	if (this->key)
	{
		CRYPTO_add(&this->key->references,1,CRYPTO_LOCK_EVP_PKEY);
	}
	this->keyId = keyPair.getKeyId();
	this->engine = keyPair.getEngine();
	if (this->engine)
	{
		ENGINE_up_ref(this->engine);
	}
}

KeyPair::~KeyPair()
{
	if (this->key)
	{
		EVP_PKEY_free(this->key);
		this->key = NULL;
	}
	if (this->engine)
	{
		ENGINE_free(this->engine);
		this->engine = NULL;
	}
}

PublicKey* KeyPair::getPublicKey()
		throw (AsymmetricKeyException, EncodeException)
{
	PublicKey *ret;
	std::string keyTemp;
	keyTemp = this->getPublicKeyPemEncoded();
	switch (this->getAlgorithm())
	{
		case AsymmetricKey::RSA:
			ret = new RSAPublicKey(keyTemp);
			break;
		case AsymmetricKey::DSA:
			ret = new DSAPublicKey(keyTemp);
			break;
		case AsymmetricKey::ECDSA:
			ret = new ECDSAPublicKey(keyTemp);
			break;
		case AsymmetricKey::EdDSA:
			ret = new EdDSAPublicKey(keyTemp);
			break;
	}
	return ret;
}

PrivateKey* KeyPair::getPrivateKey()
		throw (AsymmetricKeyException)
{
	PrivateKey *ret;
	EVP_PKEY *pkey;
	ret = NULL;
	if (engine)
	{
		pkey = ENGINE_load_private_key(this->engine, this->keyId.c_str(), NULL, NULL);
		if (!pkey)
		{
			throw AsymmetricKeyException(AsymmetricKeyException::UNAVAILABLE_KEY, "KeyId: " + this->keyId, "KeyPair::getPrivateKey");
		}
		try
		{
			ret = new PrivateKey(pkey);
		}
		catch (...)
		{
			EVP_PKEY_free(pkey);
			throw;
		}
	}
	else
	{
		switch (this->getAlgorithm())
		{
			case AsymmetricKey::RSA:
				ret = new RSAPrivateKey(this->key);
				break;
			case AsymmetricKey::DSA:
				ret = new DSAPrivateKey(this->key);
				break;
			case AsymmetricKey::ECDSA:
				ret = new ECDSAPrivateKey(this->key);
				break;
			case AsymmetricKey::EdDSA:
				ret = new EdDSAPrivateKey(this->key);
				break;
		}
		if (ret == NULL)
		{
			throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "KeyPair::getPrivateKey");
		}
		CRYPTO_add(&this->key->references,1,CRYPTO_LOCK_EVP_PKEY);
	}
	return ret;
}

std::string KeyPair::getPemEncoded(SymmetricKey &passphrase, SymmetricCipher::OperationMode mode)
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
		throw EncodeException(EncodeException::BUFFER_CREATING, "KeyPair::getPemEncoded");
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
	wrote = PEM_write_bio_PrivateKey(buffer, this->key, cipher, NULL, 0, KeyPair::passphraseCallBack, (void *)&passphraseData);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_ENCODE, "KeyPair::getPemEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "KeyPair::getPemEncoded");
	}
	retTemp = new ByteArray(data, ndata);
	ret = retTemp->toString();
	delete retTemp;
	BIO_free(buffer);
	return ret;
}

std::string KeyPair::getPemEncoded() throw (EncodeException)
{
	BIO *buffer;
	int ndata, wrote;
	std::string ret;
	ByteArray *retTemp;
	unsigned char *data;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "KeyPair::getPemEncoded");
	}
	wrote = PEM_write_bio_PrivateKey(buffer, this->key, NULL, NULL, 0, NULL, NULL);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_ENCODE, "KeyPair::getPemEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "KeyPair::getPemEncoded");
	}
	retTemp = new ByteArray(data, ndata);
	ret = retTemp->toString();
	delete retTemp;
	BIO_free(buffer);
	return ret;
}

ByteArray KeyPair::getDerEncoded() throw (EncodeException)
{
	BIO *buffer;
	int ndata, wrote;
	ByteArray ret;
	unsigned char *data;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "KeyPair::getDerEncoded");
	}
	wrote = i2d_PrivateKey_bio(buffer, this->key);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_ENCODE, "KeyPair::getDerEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "KeyPair::getDerEncoded");
	}
	ret = ByteArray(data, ndata);
	BIO_free(buffer);
	return ret;
}

AsymmetricKey::Algorithm KeyPair::getAlgorithm() throw (AsymmetricKeyException)
{
	int nid25519 = OBJ_sn2nid("ED25519");
	int nid448 = OBJ_sn2nid("ED448");
	int nid521 = OBJ_sn2nid("ED521");
	int pkeyType = 0;

	AsymmetricKey::Algorithm type;
	if (this->key == NULL)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::SET_NO_VALUE, "KeyPair::getAlgorithm");
	}
	pkeyType = EVP_PKEY_type(this->key->type);
	switch (pkeyType)
	{
		case EVP_PKEY_RSA: /* TODO: confirmar porque tem estes dois tipos */
		case EVP_PKEY_RSA2:
			type = AsymmetricKey::RSA;
			break;
		case EVP_PKEY_DSA: /* TODO: confirmar porque tem estes quatro tipos. São mesmo diferentes ??? */
		case EVP_PKEY_DSA1:
		case EVP_PKEY_DSA2:
		case EVP_PKEY_DSA3:
		case EVP_PKEY_DSA4:
			type = AsymmetricKey::DSA;
			break;
		case EVP_PKEY_EC:
			type = AsymmetricKey::ECDSA;
			break;
//		case EVP_PKEY_DH:
//			type = AsymmetricKey::DH;
//			break;
//		case EVP_PKEY_EC:
//			type = AsymmetricKey::EC;
//			break;
		default:
			if (pkeyType != 0 && (pkeyType == nid25519 || pkeyType == nid448 || pkeyType == nid521)) {
				type = AsymmetricKey::EdDSA;
				break;
			}
			throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "There is no support for this type: " + std::string(OBJ_nid2sn(this->key->type)), "KeyPair::getAlgorithm");
	}
	return type;
}

int KeyPair::getSize() throw (AsymmetricKeyException)
{
	int ret;
	if (this->key == NULL)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::SET_NO_VALUE, "KeyPair::getSize");
	}
	/* TODO: this function will br right only for RSA, DSA and EC. The others algorithms (DH) must be used
	 * individual functions */
	ret = EVP_PKEY_size(this->key);
	if (ret == 0)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR, "KeyPair::getSize");
	}
	return ret;
}

int KeyPair::getSizeBits() throw (AsymmetricKeyException)
{
	int ret;
	if (this->key == NULL)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::SET_NO_VALUE, "KeyPair::getSizeBits");
	}
	/* TODO: this function will br right only for RSA, DSA and EC. The others algorithms (DH) must be used
	 * individual functions */
	ret = EVP_PKEY_bits(this->key);
	if (ret == 0)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR, "KeyPair::getSizeBits");
	}
	return ret;
}

int KeyPair::passphraseCallBack(char *buf, int size, int rwflag, void *u)
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

std::string KeyPair::getPublicKeyPemEncoded() throw (EncodeException)
{
	BIO *buffer;
	int ndata, wrote;
	std::string ret;
	ByteArray *retTemp;
	unsigned char *data;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "KeyPair::getPublicKeyPemEncoded");
	}
	wrote = PEM_write_bio_PUBKEY(buffer, this->key);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_ENCODE, "KeyPair::getPublicKeyPemEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "KeyPair::getPublicKeyPemEncoded");
	}
	retTemp = new ByteArray(data, ndata);
	ret = retTemp->toString();
	delete retTemp;
	BIO_free(buffer);
	return ret;
}

EVP_PKEY* KeyPair::getEvpPkey() const
{
	return this->key;
}

ENGINE* KeyPair::getEngine() const
{
	return this->engine;
}

std::string KeyPair::getKeyId() const
{
	return this->keyId;
}
