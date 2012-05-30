#include <libcryptosec/Pkcs12Factory.h>

Pkcs12* Pkcs12Factory::fromDerEncoded(ByteArray &derEncoded) throw (EncodeException)
{
	BIO *buffer;
	PKCS12 *pkcs12;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "Pkcs12::loadFromDerEncoded");
	}
	if ((unsigned int)(BIO_write(buffer, derEncoded.getDataPointer(), derEncoded.size())) != derEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "Pkcs12::loadFromDerEncoded");
	}
	pkcs12 = d2i_PKCS12_bio(buffer, NULL); /* TODO: will the second parameter work fine ? */
	if (pkcs12 == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_DECODE, "Pkcs12::loadFromDerEncoded");
	}
	BIO_free(buffer);
	
	return new Pkcs12(pkcs12);
}
