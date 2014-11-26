#include <libcryptosec/ec/BrainpoolCurveFactory.h>

BrainpoolCurveFactory::BrainpoolCurveFactory() {
//Nothing to do. This constructor is never called.
}

const Curve* BrainpoolCurveFactory::getCurve(
		BrainpoolCurveFactory::CurveName curveName) throw (BigIntegerException) {

	switch (curveName) {
	case BP160r1:
		return bp160r1();
		break;
	case BP160t1:
		return bp160t1();
		break;
	case BP192r1:
		return bp192r1();
		break;
	case BP192t1:
		return bp192t1();
		break;
	case BP224r1:
		return bp224r1();
		break;
	case BP224t1:
		return bp224t1();
		break;
	case BP256r1:
		return bp256r1();
		break;
	case BP256t1:
		return bp256t1();
		break;
	case BP320r1:
		return bp320r1();
		break;
	case BP320t1:
		return bp320t1();
		break;
	case BP384r1:
		return bp384r1();
		break;
	case BP384t1:
		return bp384t1();
		break;
	case BP512r1:
		return bp512r1();
		break;
	case BP512t1:
		return bp512t1();
		break;
	default:
		//TODO throw EC exception curve not implemented or not specified
		return NULL;
		break;

		return 0;
	}
}

const Curve* BrainpoolCurveFactory::bp160r1() throw (BigIntegerException) {
	Curve * curve = new Curve();

	curve->a = new BigInteger();
	curve->a->setHexValue("340E7BE2A280EB74E2BE61BADA745D97E8F7C300");

	curve->b = new BigInteger();
	curve->b->setHexValue("1E589A8595423412134FAA2DBDEC95C8D8675E58");

	curve->p = new BigInteger();
	curve->p->setHexValue("E95E4A5F737059DC60DFC7AD95B3D8139515620F");

	curve->x = new BigInteger();
	curve->x->setHexValue("BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3");

	curve->y = new BigInteger();
	curve->y->setHexValue("1667CB477A1A8EC338F94741669C976316DA6321");

	curve->order = new BigInteger();
	curve->order->setHexValue("E95E4A5F737059DC60DF5991D45029409E60FC09");

	curve->cofactor = new BigInteger();
	curve->cofactor->setHexValue("1");
	return curve;
}

const Curve* BrainpoolCurveFactory::bp160t1() throw (BigIntegerException) {
	Curve * curve = new Curve();

	curve->a = new BigInteger();
	curve->a->setHexValue("E95E4A5F737059DC60DFC7AD95B3D8139515620C");

	curve->b = new BigInteger();
	curve->b->setHexValue("7A556B6DAE535B7B51ED2C4D7DAA7A0B5C55F380");

	curve->p = new BigInteger();
	curve->p->setHexValue("E95E4A5F737059DC60DFC7AD95B3D8139515620F");

	curve->x = new BigInteger();
	curve->x->setHexValue("B199B13B9B34EFC1397E64BAEB05ACC265FF2378");

	curve->y = new BigInteger();
	curve->y->setHexValue("ADD6718B7C7C1961F0991B842443772152C9E0AD");

	curve->order = new BigInteger();
	curve->order->setHexValue("E95E4A5F737059DC60DF5991D45029409E60FC09");

	curve->cofactor = new BigInteger();
	curve->cofactor->setHexValue("1");
	return curve;
}

const Curve* BrainpoolCurveFactory::bp192r1() throw (BigIntegerException) {
	Curve * curve = new Curve();

	curve->a = new BigInteger();
	curve->a->setHexValue("6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF");

	curve->b = new BigInteger();
	curve->b->setHexValue("469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9");

	curve->p = new BigInteger();
	curve->p->setHexValue("C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297");

	curve->x = new BigInteger();
	curve->x->setHexValue("C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6");

	curve->y = new BigInteger();
	curve->y->setHexValue("14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F");

	curve->order = new BigInteger();
	curve->order->setHexValue("C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1");

	curve->cofactor = new BigInteger();
	curve->cofactor->setHexValue("1");
	return curve;
}

const Curve* BrainpoolCurveFactory::bp192t1() throw (BigIntegerException) {
	Curve * curve = new Curve();

	curve->a = new BigInteger();
	curve->a->setHexValue("C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86294");

	curve->b = new BigInteger();
	curve->b->setHexValue("13D56FFAEC78681E68F9DEB43B35BEC2FB68542E27897B79");

	curve->p = new BigInteger();
	curve->p->setHexValue("C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297");

	curve->x = new BigInteger();
	curve->x->setHexValue("3AE9E58C82F63C30282E1FE7BBF43FA72C446AF6F4618129");

	curve->y = new BigInteger();
	curve->y->setHexValue("097E2C5667C2223A902AB5CA449D0084B7E5B3DE7CCC01C9");

	curve->order = new BigInteger();
	curve->order->setHexValue("C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1");

	curve->cofactor = new BigInteger();
	curve->cofactor->setHexValue("1");
	return curve;
}

const Curve* BrainpoolCurveFactory::bp224r1() throw (BigIntegerException) {
	Curve * curve = new Curve();

	curve->a = new BigInteger();
	curve->a->setHexValue("68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43");

	curve->b = new BigInteger();
	curve->b->setHexValue("2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B");

	curve->p = new BigInteger();
	curve->p->setHexValue("D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF");

	curve->x = new BigInteger();
	curve->x->setHexValue("0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D");

	curve->y = new BigInteger();
	curve->y->setHexValue("58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD");

	curve->order = new BigInteger();
	curve->order->setHexValue("D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F");

	curve->cofactor = new BigInteger();
	curve->cofactor->setHexValue("1");
	return curve;
}

const Curve* BrainpoolCurveFactory::bp224t1() throw (BigIntegerException) {
	Curve * curve = new Curve();

	curve->a = new BigInteger();
	curve->a->setHexValue("D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FC");

	curve->b = new BigInteger();
	curve->b->setHexValue("4B337D934104CD7BEF271BF60CED1ED20DA14C08B3BB64F18A60888D");

	curve->p = new BigInteger();
	curve->p->setHexValue("D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF");

	curve->x = new BigInteger();
	curve->x->setHexValue("6AB1E344CE25FF3896424E7FFE14762ECB49F8928AC0C76029B4D580");

	curve->y = new BigInteger();
	curve->y->setHexValue("0374E9F5143E568CD23F3F4D7C0D4B1E41C8CC0D1C6ABD5F1A46DB4C");

	curve->order = new BigInteger();
	curve->order->setHexValue("D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F");

	curve->cofactor = new BigInteger();
	curve->cofactor->setHexValue("1");
	return curve;
}

const Curve* BrainpoolCurveFactory::bp256r1() throw (BigIntegerException) {
	Curve * curve = new Curve();

	curve->a = new BigInteger();
	curve->a->setHexValue("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9");

	curve->b = new BigInteger();
	curve->b->setHexValue("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6");

	curve->p = new BigInteger();
	curve->p->setHexValue("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377");

	curve->x = new BigInteger();
	curve->x->setHexValue("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262");

	curve->y = new BigInteger();
	curve->y->setHexValue("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997");

	curve->order = new BigInteger();
	curve->order->setHexValue("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7");

	curve->cofactor = new BigInteger();
	curve->cofactor->setHexValue("1");
	return curve;
}

///

const Curve* BrainpoolCurveFactory::bp256t1() throw (BigIntegerException) {
	return 0;
}

const Curve* BrainpoolCurveFactory::bp320r1() throw (BigIntegerException) {
	return 0;
}

const Curve* BrainpoolCurveFactory::bp320t1() throw (BigIntegerException) {
	return 0;
}

const Curve* BrainpoolCurveFactory::bp384r1() throw (BigIntegerException) {
	return 0;
}

const Curve* BrainpoolCurveFactory::bp384t1() throw (BigIntegerException) {
	return 0;
}

const Curve* BrainpoolCurveFactory::bp512r1() throw (BigIntegerException) {
	return 0;
}

const Curve* BrainpoolCurveFactory::bp512t1() throw (BigIntegerException) {
	return 0;
}
