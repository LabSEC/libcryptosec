#include <libcryptosec/Engine.h>

Engine::Engine(ENGINE *engine)
{
	this->engine = engine;
}

Engine::Engine(const Engine &engine)
{
	this->engine = engine.getEngine();
	ENGINE_up_ref(this->engine);
}

Engine::~Engine()
{
	if (this->engine)
	{
		ENGINE_free(this->engine);
	}
	this->engine = NULL;
}

std::string Engine::getId() throw (EngineException)
{
	const char *id;
	if (!(this->engine))
	{
		throw EngineException(EngineException::INVALID_ENGINE, "Engine::getId");
	}
	if (!(id = ENGINE_get_id(this->engine)))
	{
		throw EngineException(EngineException::INVALID_ENGINE, "Engine::getId", true);
	}
	return std::string(id);
}

bool Engine::testInit()
{
	int rc;
	bool ret;
	rc = ENGINE_init(this->engine);
	if (rc)
	{
		ret = true;
		ENGINE_finish(this->engine);
	}
	else
	{
		ret = false;
		ERR_clear_error();
	}
	return ret;
}

std::vector<Engine::Algorithm> Engine::getCapabilities()
{
	std::vector<Engine::Algorithm> ret;
	Engine::Algorithm algorithm;
	if (ENGINE_get_RSA(this->engine))
	{
		algorithm = Engine::RSA;
		ret.push_back(algorithm);
	}
	if (ENGINE_get_DSA(this->engine))
	{
		algorithm = Engine::DSA;
		ret.push_back(algorithm);
	}
	if (ENGINE_get_ECDSA(this->engine))
	{
		algorithm = Engine::ECDSA;
		ret.push_back(algorithm);
	}
//	if (ENGINE_get_DH(this->engine))
//	{
//		algorithm = Engine::DH;
//		ret.push_back(algorithm);
//	}
	if (ENGINE_get_RAND(this->engine))
	{
		algorithm = Engine::RAND;
		ret.push_back(algorithm);
	}
	if (ENGINE_get_ciphers(this->engine))
	{
		algorithm = Engine::CIPHERS;
		ret.push_back(algorithm);
	}
	if (ENGINE_get_digests(this->engine))
	{
		algorithm = Engine::DIGESTS;
		ret.push_back(algorithm);
	}
	return ret;
}

void Engine::setCommand(std::string key) throw (EngineException)
{
	if (!(ENGINE_ctrl_cmd_string(this->engine, key.c_str(), NULL, 0)))
	{
		throw EngineException(EngineException::SET_COMMAND, "Engine::setCommand", true);
	}
}

void Engine::setCommand(std::string key, std::string value) throw (EngineException)
{
	if (!(ENGINE_ctrl_cmd_string(this->engine, key.c_str(), value.c_str(), 0)))
	{
		throw EngineException(EngineException::SET_COMMAND, "Engine::setCommand", true);
	}
}

void Engine::setCommand(std::string key, long value) throw (EngineException)
{
	if (!(ENGINE_ctrl_cmd(this->engine, key.c_str(), value, NULL, NULL, 0)))
	{
		throw EngineException(EngineException::SET_COMMAND, "Engine::setCommand", true);
	}
}

std::vector<std::pair<Engine::CmdType, std::string> > Engine::getAvaliableCmds()
{
	std::vector<std::pair<Engine::CmdType, std::string> > ret;
	std::pair<Engine::CmdType, std::string> cmd;
	const ENGINE_CMD_DEFN *cmds;
	int i;
	
	cmds = ENGINE_get_cmd_defns(this->engine);
	i = 0;
	while (cmds[i].cmd_name != NULL)
	{
		switch (cmds[i].cmd_flags)
		{
			case ENGINE_CMD_FLAG_NUMERIC:
				cmd.first = Engine::LONG;
				break;
			case ENGINE_CMD_FLAG_STRING:
				cmd.first = Engine::STRING;
				break;
			case ENGINE_CMD_FLAG_NO_INPUT:
				cmd.first = Engine::NO_PARAMETERS;
				break;
			case ENGINE_CMD_FLAG_INTERNAL:
				cmd.first = Engine::INTERNAL_USE;
				break;
		}
		cmd.second = cmds[i].cmd_name;
		i++;
		ret.push_back(cmd);
	}
	return ret;
}

void Engine::addToEnginesList() throw (EngineException)
{
}

void Engine::removeFromEnginesList() throw (EngineException)
{
}

ENGINE* Engine::getEngine() const
{
	return this->engine;
}

std::string Engine::algorithm2Name(Engine::Algorithm algorithm)
{
	std::string ret;
	switch (algorithm)
	{
		case Engine::RSA:
			ret = "RSA";
			break;
		case Engine::DSA:
			ret = "DSA";
			break;
		case Engine::ECDSA:
			ret = "ECDSA";
			break;
		case Engine::RAND:
			ret = "RAND";
			break;
		case Engine::CIPHERS:
			ret = "CIPHERS";
			break;
		case Engine::DIGESTS:
			ret = "DIGESTS";
			break;
		case Engine::ALL:
			ret = "ALL";
			break;
		case Engine::NONE:
			ret = "NONE";
			break;
	}
	return ret;
}
