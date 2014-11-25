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
	return 0;
}

const Curve* BrainpoolCurveFactory::bp192r1() throw (BigIntegerException) {
	return 0;
}

const Curve* BrainpoolCurveFactory::bp192t1() throw (BigIntegerException) {
	return 0;
}

const Curve* BrainpoolCurveFactory::bp224r1() throw (BigIntegerException) {
	return 0;
}

const Curve* BrainpoolCurveFactory::bp224t1() throw (BigIntegerException) {
	return 0;
}

const Curve* BrainpoolCurveFactory::bp256r1() throw (BigIntegerException) {
	return 0;
}

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
