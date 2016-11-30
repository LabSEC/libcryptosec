/*
 * TimestampResponseBuilder.cpp
 *
 *  Created on: Nov 29, 2016
 *      Author: martin
 */

#include <libcryptosec/ts/TimestampResponseBuilder.h>

TimestampResponseBuilder::TimestampResponseBuilder() {
	this->ctx = TS_RESP_CTX_new();
	this->req = NULL;
	serial = 0;
}

TimestampResponseBuilder::~TimestampResponseBuilder() {
	TS_RESP_CTX_free(this->ctx);
	if(this->req != NULL)
	{
		BIO_free_all(this->req);
	}
}

void TimestampResponseBuilder::setTimestampRequest(TimestampRequest& tsreq) throw (EncodeException)
{
	ByteArray der = tsreq.getDerEncoded();

	if(this->req != NULL){
		BIO_free_all(this->req);
	}

	this->req = BIO_new(BIO_s_mem());

	if (this->req == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "TimestampResponseBuilder::setTimestampRequest");
	}

	if ((unsigned int)(BIO_write(this->req, der.getDataPointer(), der.size())) != der.size())
	{
		BIO_free_all(this->req);
		throw EncodeException(EncodeException::BUFFER_WRITING, "TimestampResponseBuilder::setTimestampRequest");
	}
}

void TimestampResponseBuilder::setSerial(long int num) {
	serial = num;
	TS_RESP_CTX_set_serial_cb(this->ctx, serial_cb, NULL);
}
