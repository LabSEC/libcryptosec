#include <libcryptosec/Engines.h>

std::vector<std::string> Engines::getEnginesList() throw (EngineException)
{
	ENGINE *e;
	const char *name;
	std::vector<std::string> ret;
	e = ENGINE_get_first();
	if (!e)
	{
		throw EngineException(EngineException::ENGINE_NOT_FOUND, "Engines::getEnginesList");
	}
	name = ENGINE_get_name(e);
	ret.push_back(name);
	while ((e = ENGINE_get_next(e)) != NULL)
	{
		name = ENGINE_get_name(e);
		ret.push_back(name);
	}
	return ret;
}

void Engines::setEngineDefault(Engine &engine, Engine::Algorithm algorithm)
		throw (EngineException)
{
	unsigned int flag;
	ENGINE *e;
	e = engine.getEngine();
	if (!e)
	{
		throw EngineException(EngineException::INVALID_ENGINE, "Engines::setEngineDefault");
	}
	flag = Engines::getAlgorithmFlags(algorithm);
	if (!(ENGINE_set_default(e, flag)))
	{
		throw EngineException(EngineException::INTERNAL_ERROR, "Engines::setEngineDefault");
	}
}

Engine* Engines::getEngineDefault(Engine::Algorithm algorithm)
		throw (EngineException)
{
	ENGINE *eng = NULL;
	switch (algorithm)
	{
		case Engine::RSA:
			eng = ENGINE_get_default_RSA();
			break;
		case Engine::DSA:
			eng = ENGINE_get_default_DSA();
			break;
//		case Engines::DH:
//			e = ENGINE_get_default_DH();
//			break;
		case Engine::RAND:
			eng = ENGINE_get_default_RAND();
			break;
//		case Engine::ECDH:
//			e = ENGINE_get_default_ECDH();
//			break;
		case Engine::ECDSA:
			eng = ENGINE_get_default_EC(); //martin: ENGINE_get_default_ECDSA ->ENGINE_get_default_EC
			break;
//		case Engine::CIPHERS:
//			e = ENGINE_get_default_CIPHERS();
//			break;
//		case Engine::DIGESTS:
//			e = ENGINE_get_default_DIGESTS();
//			break;
//		case Engine::STORE:
		case Engine::ALL:
		case Engine::NONE:
		default:
			break;
	}
	if (!eng)
	{
		throw EngineException(EngineException::ENGINE_NOT_FOUND, "Engines::getEngineDefault");
	}
	return new Engine(eng);
}

Engine* Engines::getEngineById(std::string id) throw (EngineException)
{
	ENGINE *eng;
	eng = ENGINE_by_id(id.c_str());
	if (!eng)
	{
		throw EngineException(EngineException::ENGINE_NOT_FOUND, "Engines::getEngineById", true);
	}
	return new Engine(eng);
}

void Engines::loadAllStaticEngines()
{
	ENGINE_load_builtin_engines();
}

void Engines::loadDynamicEngineSupport()
{
	ENGINE_load_dynamic();
}

unsigned int Engines::getAlgorithmFlags(Engine::Algorithm flag)
{
	unsigned int ret;
	switch (flag)
	{
		case Engine::RSA:
			ret = ENGINE_METHOD_RSA;
			break;
		case Engine::DSA:
			ret = ENGINE_METHOD_DSA;
			break;
//		case Engine::DH:
//			ret = ENGINE_METHOD_DH;
//			break;
		case Engine::RAND:
			ret = ENGINE_METHOD_RAND;
			break;
//		case Engine::ECDH:
//			ret = ENGINE_METHOD_ECDH;
//			break;
		case Engine::ECDSA:
			ret = ENGINE_METHOD_EC; //martin: ENGINE_METHOD_ECDSA -> ENGINE_METHOD_EC;
			break;
		case Engine::CIPHERS:
			ret = ENGINE_METHOD_CIPHERS;
			break;
		case Engine::DIGESTS:
			ret = ENGINE_METHOD_DIGESTS;
			break;
//		case Engine::STORE:
//			ret = ENGINE_METHOD_STORE;
//			break;
		case Engine::ALL:
			ret = ENGINE_METHOD_ALL;
			break;
		case Engine::NONE:
		default:
			ret = ENGINE_METHOD_NONE;	
	}
	return ret;
}
