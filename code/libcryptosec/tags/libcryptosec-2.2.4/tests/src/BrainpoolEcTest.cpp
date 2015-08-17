#include <libcryptosec/ECDSAKeyPair.h>
#include <libcryptosec/ec/EllipticCurve.h>
#include <libcryptosec/ec/BrainpoolCurveFactory.h>
#include <fstream>
#include "gtest.h"
#include <stdio.h>

class BrainpoolEcTest : public ::testing::Test {

protected:
	virtual void SetUp() {
	}

	void testHardcodedCurve(BrainpoolCurveFactory::CurveName curveName){
		const EllipticCurve * curve = BrainpoolCurveFactory::getCurve(curveName);
			ECDSAKeyPair keypair (*curve);
			delete(curve);
			std::string pem = keypair.getPemEncoded();
			EXPECT_TRUE(pem.size() > 0);
			//TODO melhorar testes da chave fazendo assinatura
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




TEST_F(BrainpoolEcTest, HardcodedBpTestBP160r1){

	testHardcodedCurve(BrainpoolCurveFactory::BP160r1);

}

TEST_F(BrainpoolEcTest, HardcodedBpTestBP160t1){

	testHardcodedCurve(BrainpoolCurveFactory::BP160t1);

}

TEST_F(BrainpoolEcTest, HardcodedBpTestBP192r1){

	testHardcodedCurve(BrainpoolCurveFactory::BP192r1);

}

TEST_F(BrainpoolEcTest, HardcodedBpTestBP192t1){

	testHardcodedCurve(BrainpoolCurveFactory::BP192t1);

}

TEST_F(BrainpoolEcTest, HardcodedBpTestBP224r1){

	testHardcodedCurve(BrainpoolCurveFactory::BP224r1);

}

TEST_F(BrainpoolEcTest, HardcodedBpTestBP224t1){

	testHardcodedCurve(BrainpoolCurveFactory::BP224t1);

}

TEST_F(BrainpoolEcTest, HardcodedBpTestBP256r1){

	testHardcodedCurve(BrainpoolCurveFactory::BP256r1);

}

TEST_F(BrainpoolEcTest, HardcodedBpTestBP256t1){

	testHardcodedCurve(BrainpoolCurveFactory::BP256t1);

}

TEST_F(BrainpoolEcTest, HardcodedBpTestBP320r1){

	testHardcodedCurve(BrainpoolCurveFactory::BP320r1);

}

TEST_F(BrainpoolEcTest, HardcodedBpTestBP320t1){

	testHardcodedCurve(BrainpoolCurveFactory::BP320t1);

}

TEST_F(BrainpoolEcTest, HardcodedBpTestBP384r1){

	testHardcodedCurve(BrainpoolCurveFactory::BP384r1);

}

TEST_F(BrainpoolEcTest, HardcodedBpTestBP384t1){

	testHardcodedCurve(BrainpoolCurveFactory::BP384t1);

}

TEST_F(BrainpoolEcTest, HardcodedBpTestBP512r1){

	testHardcodedCurve(BrainpoolCurveFactory::BP512r1);

}

TEST_F(BrainpoolEcTest, HardcodedBpTestBP512t1){

	testHardcodedCurve(BrainpoolCurveFactory::BP512t1);

}

TEST_F(BrainpoolEcTest, DerFormatedTestBp160r1){
	std::fstream file("files/BP160r1", ios::in|ios::binary|ios::ate);
	testKeyPairFromFile(file);
}

TEST_F(BrainpoolEcTest, DerFormatedTestBp512r1){
	std::fstream file("files/BP512r1", ios::in|ios::binary|ios::ate);
	testKeyPairFromFile(file);
}
