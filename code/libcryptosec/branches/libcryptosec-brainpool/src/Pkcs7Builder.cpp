#include <libcryptosec/Pkcs7Builder.h>

Pkcs7Builder::Pkcs7Builder()
{
	this->pkcs7 = PKCS7_new();
	this->p7bio = NULL;
}

Pkcs7Builder::~Pkcs7Builder()
{
	if (this->pkcs7)
	{
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
	}
	if (this->p7bio)
	{
		BIO_free(this->p7bio);
		this->p7bio = NULL;
	}
}

void Pkcs7Builder::update(std::string &data) throw (InvalidStateException, Pkcs7Exception)
{
	ByteArray temp;
	temp = ByteArray(data);
	this->update(temp);
}

void Pkcs7Builder::update(ByteArray &data)
		throw (InvalidStateException, Pkcs7Exception)
{
	int rc;
	if (this->state != Pkcs7Builder::INIT && this->state != Pkcs7Builder::UPDATE)
	{
		throw InvalidStateException("Pkcs7Builder::update");
	}
	if (this->state == Pkcs7Builder::INIT)
	{
		this->p7bio = PKCS7_dataInit(this->pkcs7, NULL);
		if (!this->p7bio)
		{
			this->state = Pkcs7Builder::NO_INIT;
			PKCS7_free(this->pkcs7);
			this->pkcs7 = NULL;
			throw Pkcs7Exception(Pkcs7Exception::INTERNAL_ERROR, "Pkcs7Builder::update", true);
		}
	}
	rc = BIO_write(this->p7bio, data.getDataPointer(), data.size());
	if (!rc)
	{
		this->state = Pkcs7Builder::NO_INIT;
		BIO_free(this->p7bio);
		this->p7bio = NULL;
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		throw Pkcs7Exception(Pkcs7Exception::INTERNAL_ERROR, "Pkcs7Builder::update", true);
	}
	this->state = Pkcs7Builder::UPDATE;
}

void Pkcs7Builder::doFinal(std::istream *in, std::ostream *out)
		throw (InvalidStateException, Pkcs7Exception, EncodeException)
{
	int maxSize, size, rc;
	ByteArray buf, contents;
	std::string value;
	BIO *buffer;
	int ndata, wrote;
	char *data;
	maxSize = 1024;
	if (this->state != Pkcs7Builder::INIT)
	{
		throw InvalidStateException("Pkcs7Builder::doFinal");
	}
	buf = ByteArray(maxSize);
	while ((size = in->readsome((char *)buf.getDataPointer(), maxSize)) > 0)
	{
		contents = ByteArray(buf.getDataPointer(), size);
		this->update(contents);
	}

	if (this->state != Pkcs7Builder::UPDATE)
	{
		throw InvalidStateException("Pkcs7Builder::dofinal");
	}
	rc = BIO_flush(this->p7bio);
	if (!rc)
	{
        BIO_free(this->p7bio);
		this->p7bio = NULL;
        this->state = Pkcs7Builder::NO_INIT;
        throw Pkcs7Exception(Pkcs7Exception::INTERNAL_ERROR, "Pkcs7Builder::dofinal", true);
	}
	rc = PKCS7_dataFinal(this->pkcs7, this->p7bio);
	if (!rc)
	{
		BIO_free(this->p7bio);
		this->p7bio = NULL;
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		this->state = Pkcs7Builder::NO_INIT;
		throw Pkcs7Exception(Pkcs7Exception::INTERNAL_ERROR, "Pkcs7SignedDataBuilder::dofinal", true);
	}
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		this->state = Pkcs7Builder::NO_INIT;
		BIO_free(this->p7bio);
		this->p7bio = NULL;
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		throw EncodeException(EncodeException::BUFFER_CREATING, "Pkcs7::getPemEncoded");
	}
	wrote = PEM_write_bio_PKCS7(buffer, this->pkcs7);
	if (!wrote)
	{
		BIO_free(buffer);
		this->state = Pkcs7Builder::NO_INIT;
		BIO_free(this->p7bio);
		this->p7bio = NULL;
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		throw EncodeException(EncodeException::PEM_ENCODE, "Pkcs7::getPemEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		this->state = Pkcs7Builder::NO_INIT;
		BIO_free(this->p7bio);
		this->p7bio = NULL;
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		throw EncodeException(EncodeException::BUFFER_READING, "Pkcs7::getPemEncoded");
	}
	out->write(data, ndata);
	this->state = Pkcs7Builder::NO_INIT;
	BIO_free(this->p7bio);
	this->p7bio = NULL;
	PKCS7_free(this->pkcs7);
	this->pkcs7 = NULL;
}
