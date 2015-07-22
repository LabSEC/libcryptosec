#include <libcryptosec/RSAKeyPair.h>

RSAKeyPair::RSAKeyPair(int length)
		throw (AsymmetricKeyException)
{
	RSA *rsa;
	this->key = NULL;
	this->engine = NULL;
	rsa = NULL;
	rsa = RSA_generate_key(length, RSA_F4, NULL, NULL);
	if (!rsa)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR, "RSAKeyPair::RSAKeyPair");
	}
	this->key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(this->key, rsa);
	if (!this->key)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR, "RSAKeyPair::RSAKeyPair");
	}
}

RSAKeyPair::~RSAKeyPair()
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

PublicKey* RSAKeyPair::getPublicKey()
		throw (AsymmetricKeyException, EncodeException)
{
	PublicKey *ret;
	std::string keyTemp;
	keyTemp = this->getPublicKeyPemEncoded();
	ret = new RSAPublicKey(keyTemp);
	return ret;
}

PrivateKey* RSAKeyPair::getPrivateKey()
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
			throw AsymmetricKeyException(AsymmetricKeyException::UNAVAILABLE_KEY, "KeyId: " + this->keyId, "RSAKeyPair::getPrivateKey");
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
		ret = new RSAPrivateKey(this->key);
		if (ret == NULL)
		{
			throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAKeyPair::getPrivateKey");
		}
		CRYPTO_add(&this->key->references,1,CRYPTO_LOCK_EVP_PKEY);
	}
	return ret;
}

AsymmetricKey::Algorithm RSAKeyPair::getAlgorithm()
		throw (AsymmetricKeyException)
{
	return AsymmetricKey::RSA;
}
