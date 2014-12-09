#include <libcryptosec/DSAKeyPair.h>

DSAKeyPair::DSAKeyPair(int length)
		throw (AsymmetricKeyException)
{
	DSA *dsa;
	this->key = NULL;
	this->engine = NULL;
	dsa = NULL;
	dsa = DSA_generate_parameters(length, NULL, 0, NULL, NULL, NULL, NULL);
	if (!dsa)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR, "DSAKeyPair::DSAKeyPair");
	}
	DSA_generate_key(dsa);
	if (!dsa)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR, "DSAKeyPair::DSAKeyPair");
	}
	this->key = EVP_PKEY_new();
	EVP_PKEY_assign_DSA(this->key, dsa);
	if (!this->key)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR, "DSAKeyPair::DSAKeyPair");
	}
}

DSAKeyPair::~DSAKeyPair()
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

PublicKey* DSAKeyPair::getPublicKey()
		throw (AsymmetricKeyException, EncodeException)
{
	PublicKey *ret;
	std::string keyTemp;
	keyTemp = this->getPublicKeyPemEncoded();
	ret = new DSAPublicKey(keyTemp);
	return ret;
}

PrivateKey* DSAKeyPair::getPrivateKey()
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
			throw AsymmetricKeyException(AsymmetricKeyException::UNAVAILABLE_KEY, "KeyId: " + this->keyId, "DSAKeyPair::getPrivateKey");
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
		ret = new DSAPrivateKey(this->key);
		if (ret == NULL)
		{
			throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAKeyPair::getPrivateKey");
		}
		CRYPTO_add(&this->key->references,1,CRYPTO_LOCK_EVP_PKEY);
	}
	return ret;
}

AsymmetricKey::Algorithm DSAKeyPair::getAlgorithm()
		throw (AsymmetricKeyException)
{
	return AsymmetricKey::DSA;
}
