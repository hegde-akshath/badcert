package main

import (
	"github.com/hegde-akshath/badcert"
)


func GenerateCustomCerts(outputDirectory string) {
	var badRootCARecipe *badcert.BadCertificate
        var badIntermed1CARecipe *badcert.BadCertificate
        var badLeafRecipe *badcert.BadCertificate
        var badCertificateChain BadCertificateChain

        badRootCARecipe      = BuildDefaultRootCARecipe().SetVersion1()
        badIntermed1CARecipe = BuildDefaultIntermed1CARecipe().SetVersion1()
        badLeafRecipe        = BuildDefaultLeafRecipe().SetVersion1()
        badCertificateChains := BuildBadCertificateChains(badRootCARecipe, badIntermed1CARecipe, badLeafRecipe)
        for _, badCertificateChain = range *badCertificateChains {
                testCertData := CreateTestCertData(badCertificateChain, true, true, true)
                testCertData.WriteTestCertDataJson()
        }


}
