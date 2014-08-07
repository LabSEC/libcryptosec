#ifndef EMAC_H_
#define EMAC_H_

#include <libcryptosec/Hmac.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/AsymmetricCipher.h>
#include <libcryptosec/SymmetricCipher.h>
#include <libcryptosec/exception/InvalidStateException.h>

/**
 * @defgroup Util Classes Relacionadas Utilitárias de Criptografia
 */

class Emac {

public:
	enum Cipher {
		SYMMETRIC,
		ASYMMETRIC
	};

	Emac();
	Emac(Emac::Cipher cipher);
	Emac(Emac::Cipher cipher, ByteArray hmacA, ByteArray hmacB);
	virtual ~Emac();

	void init(Emac::Cipher cipher) throw (InvalidStateException);
	void setKey(SymmetricKey key) throw (InvalidStateException);
	void setKey(RSAPublicKey key) throw (InvalidStateException);
	void update(ByteArray hmac) throw (InvalidStateException);
	void update(ByteArray hmacA, ByteArray hmacB) throw (InvalidStateException);
	ByteArray doFinal() throw (InvalidStateException);
	ByteArray doFinal(ByteArray hmacA, ByteArray hmacB) throw (InvalidStateException);
	bool verify( ByteArray hmacA, ByteArray hmacB, Emac::Cipher cipher, SymmetricKey key, ByteArray emac);
	bool verify( ByteArray hmacA, ByteArray hmacB, Emac::Cipher cipher, RSAPublicKey key, ByteArray emac);

private:
	enum State {
		NO_INIT,
		INIT,
		INIT_KEY,
		UPDATE,
		READY
	};

};

#endif
