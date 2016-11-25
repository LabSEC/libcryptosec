#include <libcryptosec/ts/TimestampRequest.h>

TimestampRequest::TimestampRequest()
{
	this->req = TS_REQ_new();
	TS_REQ_set_version(this->req, 1);
}

TimestampRequest::TimestampRequest(TS_REQ* req)
{
	this->req = req;
}

void TimestampRequest::setVersion(long version = 1){
	TS_REQ_set_version(this->req, version);
}

long TimestampRequest::getVersion() {
	return TS_REQ_get_version(this->req);
}

void TimestampRequest::setMessageImprint(ObjectIdentifier algOid, ByteArray &hash){
	X509_ALGOR* algo = X509_ALGOR_new();
	algo->algorithm = algOid.getObjectIdentifier();
	algo->parameter = ASN1_TYPE_new();
	algo->parameter->type = V_ASN1_NULL;

	TS_MSG_IMPRINT *msg_imprint = TS_MSG_IMPRINT_new();
	TS_MSG_IMPRINT_set_algo(msg_imprint, algo);

	TS_MSG_IMPRINT_set_msg(msg_imprint, hash.getDataPointer(), hash.size());

	TS_REQ_set_msg_imprint(this->req, msg_imprint);

	X509_ALGOR_free(algo);

	TS_MSG_IMPRINT_free(msg_imprint);
}

ByteArray* TimestampRequest::getMessageImprintDigest(){
	return new ByteArray(this->req->msg_imprint->hashed_msg->data, this->req->msg_imprint->hashed_msg->length);
}

ObjectIdentifier TimestampRequest::getMessageImprintDigestAlg(){
	return ObjectIdentifier(this->req->msg_imprint->hash_algo->algorithm);
}

void TimestampRequest::setNonce(BigInteger &nonce){
	TS_REQ_set_nonce(this->req, nonce.getASN1Value());

}
BigInteger TimestampRequest::getNonce(){
	return BigInteger(this->req->nonce);
}

void TimestampRequest::setCertReq(bool certReq){
	TS_REQ_set_cert_req(this->req, certReq);
}

bool TimestampRequest::getCertReq(){
	return this->req->cert_req;
}


//TimestampRequest::TimestampRequest(std::string &pemEncoded)
//		throw (EncodeException)
//{
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
//}

TimestampRequest::TimestampRequest(ByteArray &derEncoded) throw (EncodeException){
	this->req = NULL;
	BIO *buffer;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "TimestampRequest::TimestampRequest");
	}
	if ((unsigned int)(BIO_write(buffer, derEncoded.getDataPointer(), derEncoded.size())) != derEncoded.size())
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_WRITING, "TimestampRequest::TimestampRequest");
	}
	this->req = d2i_TS_REQ_bio(buffer, NULL);
	if (this->req == NULL)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_DECODE, "TimestampRequest::TimestampRequest");
	}
	BIO_free(buffer);

}

TimestampRequest::~TimestampRequest()
{
	TS_REQ_free(this->req);
}

ByteArray TimestampRequest::getDerEncoded() const throw (EncodeException){
	BIO *buffer;
	int ndata, wrote;
	ByteArray ret;
	unsigned char *data;
	buffer = BIO_new(BIO_s_mem());
	if (buffer == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_CREATING, "TimestampRequest::getDerEncoded");
	}
	wrote = i2d_TS_REQ_bio(buffer, this->req);
	if (!wrote)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::DER_ENCODE, "TimestampRequest::getDerEncoded");
	}
	ndata = BIO_get_mem_data(buffer, &data);
	if (ndata <= 0)
	{
		BIO_free(buffer);
		throw EncodeException(EncodeException::BUFFER_READING, "TimestampRequest::getDerEncoded");
	}
	ret = ByteArray(data, ndata);
	BIO_free(buffer);
	return ret;
}


//std::string TimestampRequest::toXml(std::string tab){
//	string ret = "", anAlgor, aCertReq;
//	stringstream sstring;
//
//	switch(OBJ_obj2nid(this->req->msg_imprint->hash_algo))
//	{
//		case NID_md2:
//			anAlgor = "md2";
//			break;
//
//		case NID_md4:
//			anAlgor = "md4";
//			break;
//
//		case NID_md5:
//			anAlgor = "md5";
//			break;
//
//		case NID_ripemd160:
//			anAlgor = "ripemd160";
//			break;
//
//		case NID_sha:
//			anAlgor = "sha";
//			break;
//
//		case NID_sha1:
//			anAlgor = "sha1";
//			break;
//
//		case NID_sha224:
//			anAlgor = "sha224";
//			break;
//
//		case NID_sha256:
//			anAlgor = "sha256";
//			break;
//
//		case NID_sha384:
//			anAlgor = "sha384";
//			break;
//
//		case NID_sha512:
//			anAlgor = "sha512";
//			break;
//
//		default:
//			throw MessageDigestException(MessageDigestException::INVALID_ALGORITHM, "TimeStampRequest::toXml");
//	}
//
//	if(this->req->cert_req)
//	{
//		aCertReq = "true";
//	}
//	else
//	{
//		aCertReq = "false";
//	}
//
//	ret += tab + "<TimeStampReq>\n";
//
//		ret += tab + "\t<version>\n";
//			sstring << this->req->version;
//			ret += "\t\t" + sstring.str() + "\n";
//		ret += tab + "\t</version>\n";
//
//		ret += tab +  "\t<messageImprint>\n";
//			ret += tab +  "\t\t<hashAlgorithm>\n";
//				ret += tab +  "\t\t\t" + anAlgor + "\n";
//			ret += tab +  "\t\t</hashAlgorithm>\n";
//
//			ret += tab +  "\t\t<hashedMessage>\n";
//				ret += tab +  "\t\t\t" + this->req->msg_imprint hashedMessage.toHex() + "\n";
//			ret += tab +  "\t\t</hashedMessage>\n";
//		ret += tab +  "\t</messageImprint>\n";
//
//		ret += tab +  "\t<reqPolicy>\n";
//
//			if(this->reqPolicy)
//			{
//				ret += tab +  "\t\t" + this->reqPolicy->getOid() + "\n";
//			}
//
//		ret += tab +  "\t</reqPolicy>\n";
//
//		ret += tab +  "\t<nonce>\n";
//
//			if(this->nonce)
//			{
//				ret += tab +  "\t\t" + this->nonce->toHex() + "\n";
//			}
//
//		ret += tab +  "\t</nonce>\n";
//
//		ret += tab +  "\t<certReq>\n";
//			ret += tab +  "\t\t" + aCertReq + "\n";
//		ret += tab +  "\t</certReq>\n";
//
//		ret += tab +  "\t<extensions>\n";
//			for(vector<Extension*>::size_type i = 0 ; i < this->extensions.size() ; i++)
//			{
//				ret += tab + this->extensions.at(i)->getXmlEncoded("\t\t");
//			}
//		ret += tab +  "\t</extensions>\n";
//
//	ret += tab + "</TimeStampReq>\n";
//	return ret;
//
//}

TS_REQ* TimestampRequest::getTSReq() const{
	return this->req;
}

TimestampRequest& TimestampRequest::operator =(const TimestampRequest& value){
	if (this->req)
	{
		TS_REQ_free(this->req);
	}
	this->req = TS_REQ_dup(value.getTSReq());
	return (*this);
}
bool TimestampRequest::operator ==(const TimestampRequest& value){
	return value.getDerEncoded() == this->getDerEncoded();
}
