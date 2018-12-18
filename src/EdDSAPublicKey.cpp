#include <libcryptosec/EdDSAPublicKey.h>

EdDSAPublicKey::EdDSAPublicKey(EVP_PKEY *key)
		throw (AsymmetricKeyException) : PublicKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::EdDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "EdDSAPublicKey::EdDSAPublicKey");
	}
}

EdDSAPublicKey::EdDSAPublicKey(ByteArray &derEncoded)
		throw (EncodeException, AsymmetricKeyException) : PublicKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm;
	algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::EdDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "EdDSAPublicKey::EdDSAPublicKey");
	}
}

EdDSAPublicKey::EdDSAPublicKey(std::string &pemEncoded)
		throw (EncodeException, AsymmetricKeyException) : PublicKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm;
	algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::EdDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "EdDSAPublicKey::EdDSAPublicKey");
	}
}

EdDSAPublicKey::~EdDSAPublicKey()
{
}
