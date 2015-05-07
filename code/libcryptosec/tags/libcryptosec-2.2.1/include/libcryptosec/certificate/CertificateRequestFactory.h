#ifndef CERTIFICATEREQUESTFACTORY_H_
#define CERTIFICATEREQUESTFACTORY_H_

#include <libcryptosec/certificate/CertificateRequest.h>
#include <libcryptosec/certificate/CertificateRequestSPKAC.h>
#include <libcryptosec/exception/RandomException.h>
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/NetscapeSPKIException.h>

class CertificateRequestFactory {
public:
	static CertificateRequestSPKAC* fromSPKAC(std::string &path)
		throw (EncodeException, RandomException, NetscapeSPKIException);
};

#endif /* CERTIFICATEREQUESTFACTORY_H_ */
