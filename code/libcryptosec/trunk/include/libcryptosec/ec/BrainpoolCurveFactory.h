#ifndef BRAINPOOLCURVEFACTORY_H_
#define BRAINPOOLCURVEFACTORY_H_

/* local includes */
#include "Curve.h"

 /**
 * @brief Classe para fabricação de curvas do padrão Brainpool.
 * @ingroup Util
 */
class BrainpoolCurveFactory {
public:

	enum CurveName{
	BP160r1,
	BP160t1,
	BP192r1,
	BP192t1,
	BP224r1,
	BP224t1,
	BP256r1,
	BP256t1,
	BP320r1,
	BP320t1,
	BP384r1,
	BP384t1,
	BP512r1,
	BP512t1
	};

	virtual ~BrainpoolCurveFactory(){};
	static const Curve * getCurve(BrainpoolCurveFactory::CurveName curveName) throw(BigIntegerException);

private:

	BrainpoolCurveFactory();
	static const Curve * bp160r1() throw(BigIntegerException);
	static const Curve * bp160t1() throw(BigIntegerException);
	static const Curve * bp192r1() throw(BigIntegerException);
	static const Curve * bp192t1() throw(BigIntegerException);
	static const Curve * bp224r1() throw(BigIntegerException);
	static const Curve * bp224t1() throw(BigIntegerException);
	static const Curve * bp256r1() throw(BigIntegerException);
	static const Curve * bp256t1() throw(BigIntegerException);
	static const Curve * bp320r1() throw(BigIntegerException);
	static const Curve * bp320t1() throw(BigIntegerException);
	static const Curve * bp384r1() throw(BigIntegerException);
	static const Curve * bp384t1() throw(BigIntegerException);
	static const Curve * bp512r1() throw(BigIntegerException);
	static const Curve * bp512t1() throw(BigIntegerException);
};

#endif /* BRAINPOOLCURVEFACTORY_H_ */
