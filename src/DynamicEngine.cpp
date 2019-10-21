#include <libcryptosec/DynamicEngine.h>

DynamicEngine::DynamicEngine(std::string &enginePath)
throw (EngineException) : Engine(NULL)
{
	this->engine = ENGINE_by_id("dynamic");
	if (!this->engine)
	{
		throw EngineException(EngineException::DYNAMIC_ENGINE_UNAVAILABLE, "DynamicEngine::DynamicEngine");
	}
	try
	{
		std::string key;
		key = "SO_PATH";
		this->setCommand(key, enginePath);
		key = "LOAD";
		this->setCommand(key);
	}
	catch (EngineException &ex)
	{
		ENGINE_free(this->engine);
		this->engine = NULL;
		throw EngineException(EngineException::LOAD_ENGINE_FAILED, "DynamicEngine::DynamicEngine", ex.getDetails());
	}
}

DynamicEngine::DynamicEngine(std::string &enginePath, std::string &engineId)
throw (EngineException) : Engine(NULL)
{
	this->engine = ENGINE_by_id("dynamic");
	if (!this->engine)
	{
		throw EngineException(EngineException::DYNAMIC_ENGINE_UNAVAILABLE, "DynamicEngine::DynamicEngine");
	}
	try
	{
		std::string key;
		key = "SO_PATH";
		this->setCommand(key, enginePath);
		key = "ID";
		this->setCommand(key, engineId);
		key = "LOAD";
		this->setCommand(key);
	}
	catch (EngineException &ex)
	{
		ENGINE_free(this->engine);
		this->engine = NULL;
		throw EngineException(EngineException::LOAD_ENGINE_FAILED, "DynamicEngine::DynamicEngine", ex.getDetails());
	}
}

DynamicEngine::DynamicEngine(std::string &enginePath, std::string &engineId, std::vector<std::pair<std::string, std::string> > &extraCommands)
throw (EngineException) : Engine(NULL)
{
	ENGINE_load_dynamic();
	this->engine = ENGINE_by_id("dynamic");
	if (!this->engine)
	{
		throw EngineException(EngineException::DYNAMIC_ENGINE_UNAVAILABLE, "DynamicEngine::DynamicEngine");
	}
	try
	{
		std::string key, value;
		key = "SO_PATH";
		this->setCommand(key, enginePath);
		key = "ID";
		this->setCommand(key, engineId);
		key = "LOAD";
		this->setCommand(key);
		for(unsigned int i=0;i<extraCommands.size();i++) {
			key = extraCommands[i].first;
			value = extraCommands[i].second;
			this->setCommand(key, value);
		}
	}
	catch (EngineException &ex)
	{
		ENGINE_free(this->engine);
		this->engine = NULL;
		throw EngineException(EngineException::LOAD_ENGINE_FAILED, "DynamicEngine::DynamicEngine", ex.getDetails());
	}
}


DynamicEngine::~DynamicEngine()
{
}

void DynamicEngine::addToEnginesList() throw (EngineException)
{
	if (!(ENGINE_add(this->engine)))
	{
		throw EngineException(EngineException::ADD_ENGINE_TO_LIST, "DynamicEngine::addToEnginesList");
	}
}

void DynamicEngine::removeFromEnginesList() throw (EngineException)
{
	if (!(ENGINE_remove(this->engine)))
	{
		throw EngineException(EngineException::REMOVE_ENGINE_FROM_LIST, "DynamicEngine::removeFromEnginesList");
	}
}

bool DynamicEngine::load() throw (EngineException)
{
	int rc = ENGINE_init(this->engine);
	rc &= ENGINE_set_default(this->engine, ENGINE_METHOD_ALL);
	OpenSSL_add_all_algorithms();
	return rc;
}

bool DynamicEngine::release() throw (EngineException)
{
	int rc = ENGINE_finish(this->engine);
	rc &= ENGINE_free(this->engine);
	return rc;
}
