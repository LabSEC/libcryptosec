/*
 * TimestampResponseBuilder.h
 *
 *  Created on: Nov 29, 2016
 *      Author: martin
 */

#include <openssl/ts.h>

#include <libcryptosec/ts/TimestampRequest.h>
#include <libcryptosec/Certificate/Certificate.h>

#ifndef TIMESTAMPRESPONSEBUILDER_H_
#define TIMESTAMPRESPONSEBUILDER_H_

class TimestampResponseBuilder {
public:
	TimestampResponseBuilder();
	virtual ~TimestampResponseBuilder();
	void setTimestampRequest(TimestampRequest& tsreq) throw (EncodeException);
	void setSerial(long int serial);
	void setSignerCert(Certificate &cert);
	TS_RESP* sign(PrivateKey &privateKey, MessageDigest::Algorithm messageDigestAlgorithm)
	throw (AsymmetricKeyException);
protected:
	TS_RESP_CTX* ctx;
	BIO* req;


};

long int serial;

ASN1_INTEGER *serial_cb(TS_RESP_CTX *ctx, void *data)
{
	ASN1_INTEGER * asn1serial = ASN1_INTEGER_new();
	ASN1_INTEGER_set(asn1serial, serial);
	return asn1serial;
}

#endif /* TIMESTAMPRESPONSEBUILDER_H_ */
