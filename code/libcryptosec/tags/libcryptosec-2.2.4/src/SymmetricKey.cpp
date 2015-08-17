#include <libcryptosec/SymmetricKey.h>

SymmetricKey::SymmetricKey(ByteArray &key, SymmetricKey::Algorithm algorithm)
{
	this->key = key;
	this->algorithm = algorithm;
}

SymmetricKey::SymmetricKey(const SymmetricKey &symmetricKey)
{
	this->key = symmetricKey.getEncoded();
	this->algorithm = symmetricKey.getAlgorithm();
}

SymmetricKey::~SymmetricKey()
{
}

ByteArray SymmetricKey::getEncoded() const
{
	return this->key;
}

SymmetricKey::Algorithm SymmetricKey::getAlgorithm() const
{
	return this->algorithm;
}

int SymmetricKey::getSize()
{
	return this->key.size();
}

SymmetricKey& SymmetricKey::operator =(const SymmetricKey& value)
{
    this->key = value.getEncoded();
    this->algorithm = value.getAlgorithm();
    return (*this);
}

std::string SymmetricKey::getAlgorithmName(SymmetricKey::Algorithm algorithm)
{
	std::string ret;
	switch (algorithm)
	{
		case SymmetricKey::AES_128:
			ret = "aes-128";
			break;
		case SymmetricKey::AES_192:
			ret = "aes-192";
			break;
		case SymmetricKey::AES_256:
			ret = "aes-256";
			break;
		case SymmetricKey::DES:
			ret = "des";
			break;
		case SymmetricKey::DES_EDE:
			ret = "des-ede";
			break;
		case SymmetricKey::DES_EDE3:
			ret = "des-ede3";
			break;
		case SymmetricKey::RC2:
			ret = "rc2";
			break;
		case SymmetricKey::RC4:
			ret = "rc4";
			break;
	}
	return ret;
}
