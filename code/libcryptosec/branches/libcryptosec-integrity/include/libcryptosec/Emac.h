#ifndef EMAC_H_
#define EMAC_H_

#include <libcryptosec/Hmac.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/AsymmetricCipher.h>
#include <libcryptosec/SymmetricCipher.h>

/**
 * @defgroup Util Classes Relacionadas Utilitárias de Criptografia
 */

class Emac {

public:
	Emac();
	Emac( ByteArray hmacA, ByteArray hmacB );
	virtual ~Emac();

	void init( ByteArray hmac );
	void init( ByteArray hmacA, ByteArray hmacB );
	virtual ByteArray doFinal(RSAPublicKey &key) = 0;

protected:

	enum State {
		NO_INIT,
		INIT1,
		INIT2,
		FINAL
	};

	enum Cipher {
		NO_INIT,
		SYMMETRIC,
		ASYMMETRIC
	};

};

#endif
