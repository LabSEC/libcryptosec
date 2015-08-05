#include <libcryptosec/DSAPrivateKey.h>

DSAPrivateKey::DSAPrivateKey(EVP_PKEY *key)
		throw (AsymmetricKeyException) : PrivateKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::DSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAPrivateKey::DSAPrivateKey");
	}
}

DSAPrivateKey::DSAPrivateKey(ByteArray &derEncoded)
		throw (EncodeException, AsymmetricKeyException) : PrivateKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::DSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAPrivateKey::DSAPrivateKey");
	}
}
DSAPrivateKey::DSAPrivateKey(std::string &pemEncoded)
		throw (EncodeException, AsymmetricKeyException) : PrivateKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::DSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAPrivateKey::DSAPrivateKey");
	}
}

DSAPrivateKey::DSAPrivateKey(std::string &pemEncoded, ByteArray &passphrase)
		throw (EncodeException, AsymmetricKeyException) : PrivateKey (pemEncoded, passphrase)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::DSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAPrivateKey::DSAPrivateKey");
	}
}

DSAPrivateKey::~DSAPrivateKey()
{
}
