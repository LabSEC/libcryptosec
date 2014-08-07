#include <libcryptosec/SymmetricKeyGenerator.h>

SymmetricKey* SymmetricKeyGenerator::generateKey(SymmetricKey::Algorithm alg) throw (RandomException)
{
	ByteArray key;
	key = Random::bytes(EVP_MAX_KEY_LENGTH);
	return new SymmetricKey(key, alg);
}

SymmetricKey* SymmetricKeyGenerator::generateKey(SymmetricKey::Algorithm alg, int size) throw (RandomException)
{
	ByteArray key;
	key = Random::bytes(size);
	return new SymmetricKey(key, alg);
}
