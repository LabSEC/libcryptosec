#include <openssl/ts.h>
#include <openssl/evp.h>

#include <libcryptosec/ts/TimestampRequest.h>
#include <libcryptosec/certificate/Certificate.h>

#ifndef TIMESTAMPRESPONSEBUILDER_H_
#define TIMESTAMPRESPONSEBUILDER_H_

class TimestampResponseBuilder {
public:

	enum PKIStatus {
		granted = TS_STATUS_GRANTED,
		grantedWithMods = TS_STATUS_GRANTED_WITH_MODS,
		rejection = TS_STATUS_REJECTION,
		waiting = TS_STATUS_WAITING,
		revocationWarning = TS_STATUS_REVOCATION_WARNING,
		revocationNotification = TS_STATUS_REVOCATION_NOTIFICATION
	};

	enum PKIFailureInfo {
		badAlg = TS_INFO_BAD_ALG,
		badRequest = TS_INFO_BAD_REQUEST,
		badDataFormat = TS_INFO_BAD_DATA_FORMAT,
		timeNotAvailable = TS_INFO_TIME_NOT_AVAILABLE,
		unacceptedPolicy = TS_INFO_UNACCEPTED_POLICY ,
		unacceptedExtension = TS_INFO_UNACCEPTED_EXTENSION ,
		addInfoNotAvailable = TS_INFO_ADD_INFO_NOT_AVAILABLE,
		systemFailure = TS_INFO_SYSTEM_FAILURE,
	};

	TimestampResponseBuilder();
	virtual ~TimestampResponseBuilder();
	void setTimestampRequest(TimestampRequest& tsreq) throw (EncodeException);
	void setSerial(long int serial);
	void setSignerCert(Certificate &cert);
	TS_RESP* generateFailResponse(PrivateKey &privateKey, MessageDigest::Algorithm messageDigestAlgorithm, PKIStatus status, PKIFailureInfo failInfo, string statusString = "") throw (AsymmetricKeyException);
	TS_RESP* generateGrantedResponse(PrivateKey &privateKey, MessageDigest::Algorithm messageDigestAlgorithm, PKIStatus status = granted, string statusString = "") throw (AsymmetricKeyException);
protected:
	TS_RESP_CTX* ctx;
	BIO* req;
	TS_RESP* sign(PrivateKey &privateKey, MessageDigest::Algorithm messageDigestAlgorithm) throw (AsymmetricKeyException);
	void setStatusInfo(PKIStatus status, string statusString );
};

long int serial;

ASN1_INTEGER *serial_cb(TS_RESP_CTX *ctx, void *data)
{
	ASN1_INTEGER * asn1serial = ASN1_INTEGER_new();
	ASN1_INTEGER_set(asn1serial, serial);
	return asn1serial;
}

#endif /* TIMESTAMPRESPONSEBUILDER_H_ */
