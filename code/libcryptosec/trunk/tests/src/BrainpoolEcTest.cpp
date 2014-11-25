#include <libcryptosec/ECDSAKeyPair.h>
#include <libcryptosec/ec/Curve.h>
#include <libcryptosec/ec/BrainpoolCurveFactory.h>
#include <fstream>
#include "gtest.h"
#include <stdio.h>

class BrainpoolEcTest : public ::testing::Test {

protected:
	virtual void SetUp() {
	}

	void testKeyPairFromFile(fstream &file){
		if(file.is_open()){
				/* Read file into ByteArray*/
				file.seekg (0, file.end);
				int length = file.tellg();
				file.seekg (0, file.beg);
				unsigned char * memblock = new unsigned char [length];
				file.read ((char*)memblock, length);
				file.close();
				ByteArray b(memblock, length);
				delete[] memblock;

				/*Do crypto*/
				ECDSAKeyPair keypair(b);
				std::string pem = keypair.getPemEncoded();
				EXPECT_TRUE(pem.size() > 0);
				//TODO melhorar testes da chave fazendo assinatura
			}
			else
			{
				FAIL();
			}
	}

};




TEST_F(BrainpoolEcTest, HardcodedBpTest){

	const Curve * curve = BrainpoolCurveFactory::getCurve(BrainpoolCurveFactory::BP160r1);
	ECDSAKeyPair keypair (*curve);
	std::string pem = keypair.getPemEncoded();
	EXPECT_TRUE(pem.size() > 0);
	//TODO melhorar testes da chave fazendo assinatura

}

TEST_F(BrainpoolEcTest, DerFormatedTestBp160r1){
	std::fstream file("files/BP160r1", ios::in|ios::binary|ios::ate);
	testKeyPairFromFile(file);
}

TEST_F(BrainpoolEcTest, DerFormatedTestBp512r1){
	std::fstream file("files/BP512r1", ios::in|ios::binary|ios::ate);
	testKeyPairFromFile(file);
}
