#include <libcryptosec/SmartcardReader.h>

bool SmartcardReader::initialized = false;
SmartcardReader* SmartcardReader::instance = NULL;
std::string SmartcardReader::pkcs11ModulePath = "";

SmartcardReader::SmartcardReader(std::string &pkcs11ModulePath)
		throw (SmartcardModuleException)
{
	int rc;
	unsigned int nslots = 0;
	PKCS11_SLOT *slots = NULL;
	this->ctx = PKCS11_CTX_new();
	rc = PKCS11_CTX_load(this->ctx, pkcs11ModulePath.c_str());
	if (rc < 0){
		PKCS11_CTX_free(this->ctx);
		throw SmartcardModuleException(SmartcardModuleException::INVALID_PKCS11_MODULE, pkcs11ModulePath, "SmartcardReader::SmartcardReader");
	}
	rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
	if (rc < 0 || (slots == NULL)){
		PKCS11_CTX_unload(this->ctx);
        PKCS11_CTX_free(this->ctx);
		throw SmartcardModuleException(SmartcardModuleException::SMARTCARD_READER_NOT_AVAILABLE, "SmartcardReader::SmartcardReader");
	}
	PKCS11_release_all_slots(this->ctx, slots, nslots);
}

SmartcardReader::~SmartcardReader()
{
	if (SmartcardReader::instance)
	{
		PKCS11_CTX_unload(this->ctx);
		PKCS11_CTX_free(this->ctx);
	}
}

void SmartcardReader::initialize(std::string pkcs11ModulePath)
		throw (InvalidStateException, SmartcardModuleException)
{
	if (SmartcardReader::initialized)
	{
		throw InvalidStateException("SmartcardReader::initialize");
	}
	SmartcardReader::instance = new SmartcardReader(pkcs11ModulePath);
	SmartcardReader::initialized = true;
	SmartcardReader::pkcs11ModulePath = pkcs11ModulePath;
}

void SmartcardReader::destroy() throw (InvalidStateException)
{
	if (!SmartcardReader::initialized)
	{
		throw InvalidStateException("SmartcardReader::destroy");
	}
	delete SmartcardReader::instance;
	SmartcardReader::initialized = false;
	SmartcardReader::pkcs11ModulePath = "";
}

SmartcardReader* SmartcardReader::getInstance() throw (InvalidStateException, SmartcardModuleException)
{
	if (!SmartcardReader::initialized)
	{
		throw InvalidStateException("SmartcardReader::getInstance"); 
	}
	delete SmartcardReader::instance;
	try
	{
		SmartcardReader::instance = new SmartcardReader(SmartcardReader::pkcs11ModulePath);
	}
	catch(SmartcardModuleException& ex)
	{
		SmartcardReader::initialized = false;
		SmartcardReader::pkcs11ModulePath = "";
		throw SmartcardModuleException("SmartcardReader::getInstance");
	}			
	return SmartcardReader::instance;
}

SmartcardSlots* SmartcardReader::getSmartcardSlots() throw (SmartcardModuleException)
{
	int rc;
	unsigned int nslots;
	PKCS11_SLOT *slots;
	SmartcardSlots *ret;
	rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
	if (rc < 0 || (slots == NULL)){
		throw SmartcardModuleException(SmartcardModuleException::SMARTCARD_READER_NOT_AVAILABLE, "SmartcardReader::getSmartcardSlots");
	}
	ret = new SmartcardSlots(this->ctx, slots, nslots);
	return ret;
}
