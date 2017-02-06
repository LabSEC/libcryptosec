#include <libcryptosec/certificate/CertificateRequestFactory.h>

CertificateRequestSPKAC* CertificateRequestFactory::fromSPKAC(std::string &path)
	throw (EncodeException, RandomException, NetscapeSPKIException)
{
	STACK_OF(CONF_VALUE) *sk=NULL;
	LHASH_OF(CONF_VALUE) *parms=NULL;
	X509_REQ *req=NULL;
	CONF_VALUE *cv=NULL;
	NETSCAPE_SPKI *spki = NULL;
	X509_REQ_INFO *ri;
	char *type,*buf;
	EVP_PKEY *pktmp=NULL;
	X509_NAME *n=NULL;
	unsigned long chtype = MBSTRING_ASC;
	int i;
	long errline;
	int nid;
	CertificateRequestSPKAC* ret=NULL;

	/*
	 * Load input file into a hash table.  (This is just an easy
	 * way to read and parse the file, then put it into a convenient
	 * STACK format).
	 */
	parms=CONF_load(NULL,path.c_str(),&errline);
	if (parms == NULL)
	{
		throw EncodeException(EncodeException::BUFFER_READING, "CertificateRequestFactory::fromSPKAC");
	}

	sk=CONF_get_section(parms, "default");
	if (sk_CONF_VALUE_num(sk) == 0)
	{
		if (parms != NULL) CONF_free(parms);
		throw EncodeException(EncodeException::BUFFER_READING, "CertificateRequestFactory::fromSPKAC");
	}

	/*
	 * Now create a dummy X509 request structure.  We don't actually
	 * have an X509 request, but we have many of the components
	 * (a public key, various DN components).  The idea is that we
	 * put these components into the right X509 request structure
	 * and we can use the same code as if you had a real X509 request.
	 */
	req=X509_REQ_new();
	if (req == NULL)
	{
		if (parms != NULL) CONF_free(parms);
		throw RandomException(RandomException::INTERNAL_ERROR, "CertificateRequestFactory::fromSPKAC");
	}

	/*
	 * Build up the subject name set.
	 */
	n = X509_REQ_get_subject_name(req);

	for (i = 0; ; i++)
	{
		if (sk_CONF_VALUE_num(sk) <= i) break;

		cv=sk_CONF_VALUE_value(sk,i);
		type=cv->name;
		/* Skip past any leading X. X: X, etc to allow for
		 * multiple instances
		 */
		for (buf = cv->name; *buf ; buf++)
			if ((*buf == ':') || (*buf == ',') || (*buf == '.'))
			{
				buf++;
				if (*buf) type = buf;
				break;
			}

		buf=cv->value;
		if ((nid=OBJ_txt2nid(type)) == NID_undef)
		{
			if (strcmp(type, "SPKAC") == 0)
			{
				spki = NETSCAPE_SPKI_b64_decode(cv->value, -1);
				if (spki == NULL)
				{
					if (parms != NULL) CONF_free(parms);
					throw EncodeException(EncodeException::BASE64_DECODE, "CertificateRequestFactory::fromSPKAC");
				}
			}
			continue;
		}

		if (!X509_NAME_add_entry_by_NID(n, nid, chtype, (unsigned char *)buf, -1, -1, 0))
		{
			if (parms != NULL) CONF_free(parms);
			if (spki != NULL) NETSCAPE_SPKI_free(spki);
			throw RandomException(RandomException::INTERNAL_ERROR, "CertificateRequestFactory::fromSPKAC");
		}
	}
	if (spki == NULL)
	{
		if (parms != NULL) CONF_free(parms);
		throw NetscapeSPKIException(NetscapeSPKIException::SET_NO_VALUE, "CertificateRequestFactory::fromSPKAC");
	}

	/*
	 * Now extract the key from the SPKI structure.
	 */
	if ((pktmp=NETSCAPE_SPKI_get_pubkey(spki)) == NULL)
	{
		if (parms != NULL) CONF_free(parms);
		if (spki != NULL) NETSCAPE_SPKI_free(spki);
		throw NetscapeSPKIException(NetscapeSPKIException::SET_NO_VALUE, "CertificateRequestFactory::fromSPKAC");
	}
	X509_REQ_set_pubkey(req,pktmp);
	EVP_PKEY_free(pktmp);

	ret = new CertificateRequestSPKAC(req, spki);

	return ret;
}
