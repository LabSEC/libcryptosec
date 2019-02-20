#include <libcryptosec/certificate/BasicConstraintsExtension.h>

BasicConstraintsExtension::BasicConstraintsExtension() : Extension()
{
	this->ca = false;
	this->pathLen = -1;
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_basic_constraints);
}

BasicConstraintsExtension::BasicConstraintsExtension(X509_EXTENSION *ext)
		throw (CertificationException) : Extension(ext)
{
	BASIC_CONSTRAINTS_st *basicConstraints;
	if (OBJ_obj2nid(X509_EXTENSION_get_object(ext)) != NID_basic_constraints)
	{
		throw CertificationException(CertificationException::INVALID_TYPE, "BasicConstraintsExtension::BasicConstraintsExtension");
	}
	basicConstraints = (BASIC_CONSTRAINTS_st *)X509V3_EXT_d2i(ext);
	this->ca = basicConstraints->ca?true:false;
	if (basicConstraints->pathlen)
	{
		this->pathLen = ASN1_INTEGER_get(basicConstraints->pathlen);
	}
	else
	{
		this->pathLen = -1;
	}
	BASIC_CONSTRAINTS_free(basicConstraints);
}

BasicConstraintsExtension::~BasicConstraintsExtension()
{
}

std::string BasicConstraintsExtension::extValue2Xml(std::string tab)
{
	std::string ret, string;
	char temp[15];
	long value;

	string = (this->isCa())?"true":"false";
	ret += tab + "<ca>" + string + "</ca>\n";
	try
	{
		value = this->getPathLen();
		sprintf(temp, "%d", (int)value);
		string = temp;
		ret += tab + "<pathLenConstraint>" + string + "</pathLenConstraint>\n";
	}
	catch (...)
	{
	}
	
	return ret;	
}

/**
 * @deprecated
 * Retorna o conteudo da extensão em formato XML.
 * Esta função será substituida por toXml().
 * */
std::string BasicConstraintsExtension::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string BasicConstraintsExtension::getXmlEncoded(std::string tab)
{
	std::string ret, string;
	char temp[15];
	long value;
	ret = tab + "<basicConstraints>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";
			string = (this->isCa())?"true":"false";
			ret += tab + "\t\t<ca>" + string + "</ca>\n";
			try
			{
				value = this->getPathLen();
				sprintf(temp, "%d", (int)value);
				string = temp;
				ret += tab + "\t\t<pathLenConstraint>" + string + "</pathLenConstraint>\n";
			}
			catch (...)
			{
			}
		ret += tab + "\t</extnValue>\n";
	ret += tab + "</basicConstraints>\n";
	return ret;
}

void BasicConstraintsExtension::setCa(bool value)
{
	this->ca = value;
}

bool BasicConstraintsExtension::isCa()
{
	return this->ca;
}

void BasicConstraintsExtension::setPathLen(long value)
{
	this->pathLen = value;
}

long BasicConstraintsExtension::getPathLen()
{
	return this->pathLen;
}

X509_EXTENSION* BasicConstraintsExtension::getX509Extension()
{
	X509_EXTENSION *ret;
	BASIC_CONSTRAINTS_st *basicConstraints;
	basicConstraints = BASIC_CONSTRAINTS_new();
	basicConstraints->ca = this->ca?255:0;
	if (this->pathLen >= 0)
	{
		basicConstraints->pathlen = ASN1_INTEGER_new();
		ASN1_INTEGER_set(basicConstraints->pathlen, this->pathLen);
	}
	ret = X509V3_EXT_i2d(NID_basic_constraints, this->critical?1:0, (void *)basicConstraints);
	BASIC_CONSTRAINTS_free(basicConstraints);
	return ret;
}
