/*
 * TimestampResponse.h
 *
 *  Created on: Nov 29, 2016
 *      Author: martin
 */

#ifndef TIMESTAMPRESPONSE_H_
#define TIMESTAMPRESPONSE_H_

#include <openssl/ts.h>

#include <libcryptosec/ByteArray.h>
#include <libcryptosec/exception/EncodeException.h>

class TimestampResponse {
public:
	TimestampResponse();
	TimestampResponse(TS_RESP* resp);
	TimestampResponse(ByteArray& derEncoded) throw (EncodeException);
	virtual ~TimestampResponse();
	ByteArray getDerEncoded() const throw (EncodeException);
protected:
	TS_RESP *resp;
};

#endif /* TIMESTAMPRESPONSE_H_ */
