#include <libcryptosec/ts/TimestampRequest.h>

TimestampRequest::TimestampRequest()
{
	this->req = TS_REQ_new();
}

TimestampRequest::TimestampRequest(TS_REQ* req)
{
	this->req = req;
}

TimestampRequest::TimestampRequest(std::string &pemEncoded)
		throw (EncodeException)
{
	/*BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "TimestampRequest::TimestampRequest");
	}
	if ((unsigned int)(BIO_write(buffer, pemEncoded.c_str(), pemEncoded.size())) != pemEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "TimestampRequest::TimestampRequest");
	}
	this->req = PEM_read_bio_X509_REQ(buffer, NULL, NULL, NULL);
	if (this->req == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::PEM_DECODE, "TimestampRequest::TimestampRequest");
	}
	BIO_free(buffer);*/
}

TimestampRequest::~TimestampRequest()
{
	TS_REQ_free(this->req);
}
