#include <libcryptosec/ECDSAPrivateKey.h>

ECDSAPrivateKey::ECDSAPrivateKey(EVP_PKEY *key)
		throw (AsymmetricKeyException) : PrivateKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::ECDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPrivateKey::ECDSAPrivateKey");
	}
}

ECDSAPrivateKey::ECDSAPrivateKey(ByteArray &derEncoded)
		throw (EncodeException, AsymmetricKeyException) : PrivateKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::ECDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPrivateKey::ECDSAPrivateKey");
	}
}
ECDSAPrivateKey::ECDSAPrivateKey(std::string &pemEncoded)
		throw (EncodeException, AsymmetricKeyException) : PrivateKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::ECDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPrivateKey::ECDSAPrivateKey");
	}
}

ECDSAPrivateKey::ECDSAPrivateKey(std::string &pemEncoded, ByteArray &passphrase)
		throw (EncodeException, AsymmetricKeyException) : PrivateKey (pemEncoded, passphrase)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::ECDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPrivateKey::ECDSAPrivateKey");
	}
}

ECDSAPrivateKey::~ECDSAPrivateKey()
{
}
