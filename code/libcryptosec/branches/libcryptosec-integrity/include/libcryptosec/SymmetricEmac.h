#ifndef SYMMETRICEMAC_H_
#define SYMMETRICEMAC_H_

class SymmetricEmac {

public:
	SymmetricEmac();
	virtual ~SymmetricEmac();

protected:
	enum State {
		NO_INIT,
		INIT,
		UPDATE,
	};

	SymmetricKey key;

};

#endif
