#include <libcryptosec/certificate/RevokedCertificate.h>

RevokedCertificate::RevokedCertificate()
{
	this->certificateSerialNumber = BigInteger();
	this->reasonCode = RevokedCertificate::UNSPECIFIED;
}

RevokedCertificate::RevokedCertificate(X509_REVOKED *revoked)
{
	ASN1_ENUMERATED* asn1Enumerated;
	if (revoked)
	{
		if (revoked->serialNumber)
		{
			this->certificateSerialNumber = BigInteger(revoked->serialNumber);
		}
		else
		{
			this->certificateSerialNumber = BigInteger();
		}
		if (revoked->revocationDate)
		{
			this->revocationDate = DateTime(revoked->revocationDate);
		}
		asn1Enumerated = (ASN1_ENUMERATED*) X509_REVOKED_get_ext_d2i(revoked, NID_crl_reason, NULL, NULL);
		if (asn1Enumerated != NULL)
		{
			this->reasonCode = (RevokedCertificate::ReasonCode)ASN1_ENUMERATED_get(asn1Enumerated);
			ASN1_ENUMERATED_free(asn1Enumerated);
		}
		else
		{
			this->reasonCode = RevokedCertificate::UNSPECIFIED;
		}
	}
	else
	{
		this->certificateSerialNumber = 0;
		this->reasonCode = RevokedCertificate::UNSPECIFIED;
	}
}

RevokedCertificate::~RevokedCertificate()
{
}

std::string RevokedCertificate::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string RevokedCertificate::getXmlEncoded(std::string tab)
{
	std::string ret;
	
	ret = tab + "<revokedCertificate>\n";
		ret += tab + "\t<certificateSerialNumber>" + this->certificateSerialNumber.toDec() + "</certificateSerialNumber>\n";
		ret += tab + "\t<revocationDate>" + this->revocationDate.getXmlEncoded() + "</revocationDate>\n";
		if (this->reasonCode != RevokedCertificate::UNSPECIFIED)
		{
			ret += tab + "\t<reason>" + RevokedCertificate::reasonCode2Name(this->reasonCode) + "</reason>\n";
		}
	ret += tab + "</revokedCertificate>\n";
	return ret;
}

void RevokedCertificate::setCertificateSerialNumber(long certificateSerialNumber)
	throw(BigIntegerException)
{
	this->certificateSerialNumber = BigInteger(certificateSerialNumber);
}

void RevokedCertificate::setCertificateSerialNumber(BigInteger certificateSerialNumber)
{
	this->certificateSerialNumber = certificateSerialNumber;
}

long RevokedCertificate::getCertificateSerialNumber()
{
	return this->certificateSerialNumber.getValue();
}

BigInteger RevokedCertificate::getCertificateSerialNumberBigInt()
{
	return this->certificateSerialNumber;
}

void RevokedCertificate::setRevocationDate(DateTime &revocationDate)
{
	this->revocationDate = revocationDate;
}

DateTime RevokedCertificate::getRevocationDate()
{
	return this->revocationDate;
}

void RevokedCertificate::setReasonCode(RevokedCertificate::ReasonCode reasonCode)
{
	this->reasonCode = reasonCode;
}

RevokedCertificate::ReasonCode RevokedCertificate::getReasonCode()
{
	return this->reasonCode;
}

X509_REVOKED* RevokedCertificate::getX509Revoked()
{
	X509_REVOKED *ret;
	ASN1_ENUMERATED *asn1Enumerated;
	ret = X509_REVOKED_new();
	
	ret->serialNumber = this->certificateSerialNumber.getASN1Value();
	
	ret->revocationDate = this->revocationDate.getAsn1Time();
	
	if (this->reasonCode != RevokedCertificate::UNSPECIFIED)
	{
		asn1Enumerated = ASN1_ENUMERATED_new();
		ASN1_ENUMERATED_set(asn1Enumerated, this->reasonCode);
		X509_REVOKED_add1_ext_i2d(ret, NID_crl_reason, asn1Enumerated, 0, 0);
		ASN1_ENUMERATED_free(asn1Enumerated);
	}
	return ret;
}

std::string RevokedCertificate::reasonCode2Name(RevokedCertificate::ReasonCode reasonCode)
{
	std::string ret;
	switch (reasonCode)
	{
		case RevokedCertificate::UNSPECIFIED:
			ret = "unspecified";
			break;
		case RevokedCertificate::KEY_COMPROMISE:
			ret = "keyCompromise";
			break;
		case RevokedCertificate::CA_COMPROMISE:
			ret = "caCompromise";
			break;
	    case RevokedCertificate::AFFILIATION_CHANGED:
			ret = "affiliationChanged";
			break;
	    case RevokedCertificate::SUPER_SEDED:
			ret = "superSeded";
			break;
	    case RevokedCertificate::CESSATION_OF_OPERATION:
			ret = "cessationOfOperation";
			break;
	    case RevokedCertificate::CERTIFICATE_HOLD:
			ret = "certificateHold";
			break;
	    case RevokedCertificate::PRIVILEGE_WITH_DRAWN:
			ret = "privilegeWithDrawn";
			break;
	    case RevokedCertificate::AACOMPROMISE:
			ret = "aACompromise";
			break;
	}
	return ret;
}
