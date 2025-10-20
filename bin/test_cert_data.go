package main

import (
	"fmt"
)

type TestCertData struct {
	certificateChain []*Certificate
	leafPresent bool
	intermedCAPresent bool
	isValid bool
}

func CreateTestCertData(badCertChain []*BadCertificate, leafPresent bool, intermedCAPresent bool, isValid bool) (testCertData *TestCertData) {
	var testCertData TestCertData
	
	testCertData.leafPresent       = leafPresent
	testCertData.intermedCAPresent = intermedCAPresent
	testCertData.isValid           = isValid
        
	testCertData.
	for badcert, ok := range badCertChain {
	    
	}
	return (&TestCertData{badCertChain: badCertChain, leafPresent: leafPresent, intermedCAPresent: intermedCAPresent, isValid: isValid}
}


