 
//This is the main class RangeMapper. It can be used in adaptive data 
//processing. It processes ranges that passed to encoder and decoder.
//In adaptive coder the ranges can be computed dynamically and depend
//on the context. 
//Class is written for generic case: alphabets from 2 up to 10000 can be
//processed without changes in code. In case of special data coder can
//be optimized and run at least twice faster. 
class RangeMapper {
public:
	RangeMapper(int range_size) {
		LOW = 0; 
		MID = 0; 
		RANGE_SIZE = range_size;
		RANGE_LIMIT = ((unsigned long long)(1) << RANGE_SIZE);
		BYTES_IN_BUFFER = (64 - RANGE_SIZE) / 8;
		SHIFT = (BYTES_IN_BUFFER - 1) * 8;
		MASK  = ((long long)(1)<<(BYTES_IN_BUFFER * 8)) - 1;
		HIGH = MASK;
	}
	~RangeMapper() {}
	void encodeRange(int cmin, int cmax);
	void decodeRange(int cmin, int cmax);
	int getMidPoint();
	void flush();
	void init();
private:
	void updateModel(int cmin, int cmax);
	unsigned long long LOW, HIGH, MID, RANGE_LIMIT, MASK;
	unsigned char RANGE_SIZE, SHIFT, BYTES_IN_BUFFER;
};

void makeRanges(unsigned char* data, int data_size, int* cm, int alphabet_size, int PRECISION);

void makeLookupTable(int* cm, int size, short* lookup);