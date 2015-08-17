#include <libcryptosec/RSAPrivateKey.h>

RSAPrivateKey::RSAPrivateKey(EVP_PKEY *key)
		throw (AsymmetricKeyException) : PrivateKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPrivateKey::RSAPrivateKey");
	}
}

RSAPrivateKey::RSAPrivateKey(ByteArray &derEncoded)
			throw (EncodeException, AsymmetricKeyException) : PrivateKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPrivateKey::RSAPrivateKey");
	}
}
RSAPrivateKey::RSAPrivateKey(std::string &pemEncoded)
		throw (EncodeException, AsymmetricKeyException) : PrivateKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPrivateKey::RSAPrivateKey");
	}
}

RSAPrivateKey::RSAPrivateKey(std::string &pemEncoded, ByteArray &passphrase)
		throw (EncodeException, AsymmetricKeyException) : PrivateKey(pemEncoded, passphrase)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPrivateKey::RSAPrivateKey");
	}
}

RSAPrivateKey::~RSAPrivateKey()
{
}
