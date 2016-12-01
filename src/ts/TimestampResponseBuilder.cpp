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

void TimestampResponseBuilder::setSignerCert(Certificate &cert){
	TS_RESP_CTX_set_signer_cert(this->ctx, X509_dup(cert.getX509()));
}

void TimestampResponseBuilder::setSerial(long int num) {
	serial = num;
	TS_RESP_CTX_set_serial_cb(this->ctx, serial_cb, NULL);
}

void TimestampResponseBuilder::setStatusInfo(PKIStatus status, string statusString){
	if(statusString.compare("")){
		TS_RESP_CTX_set_status_info(this->ctx, (int)status, NULL);
	}
	else {
		TS_RESP_CTX_set_status_info(this->ctx, (int)status, statusString.c_str());
	}
}

TS_RESP* TimestampResponseBuilder::generateFailResponse(PrivateKey &privateKey, MessageDigest::Algorithm messageDigestAlgorithm,
		PKIStatus status, PKIFailureInfo failInfo, string statusString) throw (AsymmetricKeyException){

	TS_RESP* ret = NULL;

	if(status != granted && status != grantedWithMods)
	{
		this->setStatusInfo(status, statusString);
		TS_RESP_CTX_add_failure_info(this->ctx,(int)failInfo);
		ret = this->sign(privateKey, messageDigestAlgorithm);
	}

	return ret;
}
TS_RESP* TimestampResponseBuilder::generateGrantedResponse(PrivateKey &privateKey, MessageDigest::Algorithm messageDigestAlgorithm,
		PKIStatus status, string statusString) throw (AsymmetricKeyException) {

	TS_RESP* ret = NULL;

	if(status == granted || status == grantedWithMods)
	{
		this->setStatusInfo(status, statusString);
		ret = this->sign(privateKey, messageDigestAlgorithm);
	}

	return ret;
}

TS_RESP* TimestampResponseBuilder::sign(PrivateKey &privateKey, MessageDigest::Algorithm messageDigestAlgorithm)
	throw (AsymmetricKeyException) {
	TS_RESP_CTX_set_signer_key(this->ctx, privateKey.getEvpPkey());

	if(this->ctx-> != NULL){
		EVP_MD_CTX_free(this-)
	}
}
