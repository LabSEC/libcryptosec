#include <libcryptosec/Random.h>

ByteArray Random::bytes(int nbytes) throw (RandomException)
{
	int rc;
	ByteArray ret;
	ret = ByteArray(nbytes);
	rc = RAND_bytes(ret.getDataPointer(), nbytes);
	if (rc == -1)
	{
		throw RandomException(RandomException::NO_IMPLEMENTED_FUNCTION, "Random::bytes");
	}
	else if (rc == 0)
	{
		throw RandomException(RandomException::NO_DATA_SEEDED, "Random::bytes");
	}
	return ret;
}

ByteArray Random::pseudoBytes(int nbytes) throw (RandomException)
{
	int rc;
	ByteArray ret;
	ret = ByteArray(nbytes);
	rc = RAND_pseudo_bytes(ret.getDataPointer(), nbytes);
	if (rc == -1)
	{
		throw RandomException(RandomException::NO_IMPLEMENTED_FUNCTION, "Random::pseudoBytes");
	}
	else if (rc == 0)
	{
		throw RandomException(RandomException::NO_DATA_SEEDED, "Random::pseudoBytes");
	}
	return ret;
}

void Random::seedData(ByteArray &data)
{
	RAND_seed(data.getDataPointer(), data.size());
}

void Random::seedFile(std::string &filename, int nbytes) throw (RandomException)
{
	int rc;
	rc = RAND_load_file(filename.c_str(), nbytes);
	if (!rc)
	{
		throw RandomException(RandomException::INTERNAL_ERROR, "Random::seedFile");
	}
}

void Random::cleanSeed()
{
	RAND_cleanup();
}

bool Random::status()
{
	return (RAND_status())?true:false;
}
