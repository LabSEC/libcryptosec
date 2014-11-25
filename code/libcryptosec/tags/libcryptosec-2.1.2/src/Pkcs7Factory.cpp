#include <libcryptosec/Pkcs7Factory.h>

Pkcs7* Pkcs7Factory::fromDerEncoded(ByteArray &derEncoded)
		throw (Pkcs7Exception, EncodeException)
{
	BIO *buffer;
	PKCS7 *pkcs7;
	Pkcs7 *ret;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "Pkcs7::loadFromDerEncoded");
	}
	if ((unsigned int)(BIO_write(buffer, derEncoded.getDataPointer(), derEncoded.size())) != derEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "Pkcs7::loadFromDerEncoded");
	}
	pkcs7 = d2i_PKCS7_bio(buffer, NULL); /* TODO: will the second parameter work fine ? */
	if (pkcs7 == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_DECODE, "Pkcs7::loadFromDerEncoded");
	}
	BIO_free(buffer);
	switch (OBJ_obj2nid(pkcs7->type))
	{
		case NID_pkcs7_signed:
			ret = new Pkcs7SignedData(pkcs7);
			break;
		case NID_pkcs7_enveloped:
			ret = new Pkcs7EnvelopedData(pkcs7);
			break;
		default:
			PKCS7_free(pkcs7);
			throw Pkcs7Exception(Pkcs7Exception::INVALID_TYPE, "Pkcs7::loadFromDerEncoded");
	}
	return ret;
}

Pkcs7* Pkcs7Factory::fromPemEncoded(std::string &pemEncoded)
		throw (Pkcs7Exception, EncodeException)
{
	BIO *buffer;
	PKCS7 *pkcs7;
	Pkcs7 *ret;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "Pkcs7::loadFromPemEncoded");
	}
	if ((unsigned int)(BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size())) != pemEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "Pkcs7::loadFromPemEncoded");
	}
	pkcs7 = PEM_read_bio_PKCS7(buffer, NULL, NULL, NULL);
	if (pkcs7 == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_DECODE, "Pkcs7::loadFromPemEncoded");
	}
	BIO_free(buffer);
	switch (OBJ_obj2nid(pkcs7->type))
	{
		case NID_pkcs7_signed:
			ret = new Pkcs7SignedData(pkcs7);
			break;
		case NID_pkcs7_enveloped:
			ret = new Pkcs7EnvelopedData(pkcs7);
			break;
		default:
			PKCS7_free(pkcs7);
			throw Pkcs7Exception(Pkcs7Exception::INVALID_TYPE, "Pkcs7::loadFromPemEncoded");
	}
	return ret;
}
