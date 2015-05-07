#include <libcryptosec/Pkcs7EnvelopedDataBuilder.h>

Pkcs7EnvelopedDataBuilder::Pkcs7EnvelopedDataBuilder(Certificate &cert,
			SymmetricKey::Algorithm symAlgorithm,
			SymmetricCipher::OperationMode symOperationMode)
		throw (Pkcs7Exception, SymmetricCipherException)
{
	int rc;
	PKCS7_set_type(this->pkcs7, NID_pkcs7_enveloped);
	try
	{
		rc = PKCS7_set_cipher(pkcs7, SymmetricCipher::getCipher(symAlgorithm, symOperationMode));
	}
	catch (...)
	{
		PKCS7_free(this->pkcs7);
		throw;
	}
	if (!rc)
	{
		PKCS7_free(this->pkcs7);
		throw Pkcs7Exception(Pkcs7Exception::INVALID_SYMMETRIC_CIPHER, "Pkcs7EnvelopedDataBuilder::Pkcs7EnvelopedDataBuilder");
	}
	if (!PKCS7_add_recipient(this->pkcs7, cert.getX509()))
	{
		PKCS7_free(this->pkcs7);
		throw Pkcs7Exception(Pkcs7Exception::INVALID_CERTIFICATE, "Pkcs7EnvelopedDataBuilder::Pkcs7EnvelopedDataBuilder");
	}
	this->state = Pkcs7Builder::INIT;
}

Pkcs7EnvelopedDataBuilder::~Pkcs7EnvelopedDataBuilder()
{
}

void Pkcs7EnvelopedDataBuilder::init(Certificate &cert,
			SymmetricKey::Algorithm symAlgorithm,
			SymmetricCipher::OperationMode symOperationMode)
		throw (Pkcs7Exception, SymmetricCipherException)
{
	int rc;
	if (this->state != Pkcs7Builder::NO_INIT)
	{
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		if (this->state == Pkcs7Builder::UPDATE)
		{
			BIO_free(this->p7bio);
			this->p7bio = NULL;
		}
	}
	this->pkcs7 = PKCS7_new();
	PKCS7_set_type(this->pkcs7, NID_pkcs7_enveloped);
	try
	{
		rc = PKCS7_set_cipher(pkcs7, SymmetricCipher::getCipher(symAlgorithm, symOperationMode));
	}
	catch (...)
	{
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		throw;
	}
	if (!rc)
	{
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		throw Pkcs7Exception(Pkcs7Exception::INVALID_SYMMETRIC_CIPHER, "Pkcs7EnvelopedDataBuilder::init");
	}
	if (!PKCS7_add_recipient(this->pkcs7, cert.getX509()))
	{
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		throw Pkcs7Exception(Pkcs7Exception::INVALID_CERTIFICATE, "Pkcs7EnvelopedDataBuilder::init");
	}
	this->state = Pkcs7Builder::INIT;
}

void Pkcs7EnvelopedDataBuilder::addCipher(Certificate &certificate)
	throw (InvalidStateException, Pkcs7Exception)
{
	if (this->state != Pkcs7Builder::INIT)
	{
		throw InvalidStateException("Pkcs7EnvelopedDataBuilder::addCipher");
	}
	if (!PKCS7_add_recipient(this->pkcs7, certificate.getX509()))
	{
		this->state = Pkcs7Builder::NO_INIT;
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		throw Pkcs7Exception(Pkcs7Exception::INVALID_CERTIFICATE, "Pkcs7EnvelopedDataBuilder::addCipher");
	}
}

Pkcs7EnvelopedData* Pkcs7EnvelopedDataBuilder::doFinal()
		throw (InvalidStateException, Pkcs7Exception)
{
	int rc;
	Pkcs7EnvelopedData *ret;
	if (this->state != Pkcs7Builder::UPDATE)
	{
		throw InvalidStateException("Pkcs7EnvelopedDataBuilder::dofinal");
	}
	rc = BIO_flush(this->p7bio);
	if (!rc)
	{
        BIO_free(this->p7bio);
		this->p7bio = NULL;
        PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
        this->state = Pkcs7Builder::NO_INIT;
        throw Pkcs7Exception(Pkcs7Exception::INTERNAL_ERROR, "Pkcs7EnvelopedDataBuilder::dofinal");
	}
	rc = PKCS7_dataFinal(this->pkcs7, this->p7bio);
	if (!rc)
	{
		BIO_free(this->p7bio);
		this->p7bio = NULL;
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		this->state = Pkcs7Builder::NO_INIT;
		throw Pkcs7Exception(Pkcs7Exception::INTERNAL_ERROR, "Pkcs7EnvelopedDataBuilder::dofinal");
	}
	this->state = Pkcs7Builder::NO_INIT;
	BIO_free(this->p7bio);
	this->p7bio = NULL;
	ret = new Pkcs7EnvelopedData(this->pkcs7);
	this->pkcs7 = NULL;
	return ret;
}

Pkcs7EnvelopedData* Pkcs7EnvelopedDataBuilder::doFinal(std::string &data)
		throw (InvalidStateException, Pkcs7Exception)
{
	this->update(data);
	return this->doFinal();
}

Pkcs7EnvelopedData* Pkcs7EnvelopedDataBuilder::doFinal(ByteArray &data)
		throw (InvalidStateException, Pkcs7Exception)
{
	this->update(data);
	return this->doFinal();
}
