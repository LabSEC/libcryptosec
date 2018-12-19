#include <libcryptosec/EdDSAPrivateKey.h>

EdDSAPrivateKey::EdDSAPrivateKey(EVP_PKEY *key)
		throw (AsymmetricKeyException) : PrivateKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::EdDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "EdDSAPrivateKey::EdDSAPrivateKey");
	}
}

EdDSAPrivateKey::EdDSAPrivateKey(ByteArray &derEncoded)
		throw (EncodeException, AsymmetricKeyException) : PrivateKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::EdDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "EdDSAPrivateKey::EdDSAPrivateKey");
	}
}
EdDSAPrivateKey::EdDSAPrivateKey(std::string &pemEncoded)
		throw (EncodeException, AsymmetricKeyException) : PrivateKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::EdDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "EdDSAPrivateKey::EdDSAPrivateKey");
	}
}

EdDSAPrivateKey::EdDSAPrivateKey(std::string &pemEncoded, ByteArray &passphrase)
		throw (EncodeException, AsymmetricKeyException) : PrivateKey (pemEncoded, passphrase)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::EdDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "EdDSAPrivateKey::EdDSAPrivateKey");
	}
}

EdDSAPrivateKey::~EdDSAPrivateKey()
{
}
