#pragma once

#define METHOD_TDT 0

class AnalysisMethod
{
public:
	AnalysisMethod(void);
	~AnalysisMethod(void);

	static AnalysisMethod *make_analysis_method(int choice);

	virtual int InitCompression() = 0;
	virtual int ProccessSegment() = 0;
};

