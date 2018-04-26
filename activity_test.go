package describedbinstance

import (
	"io/ioutil"
	"testing"
	"fmt"
	"github.com/TIBCOSoftware/flogo-lib/core/activity"
	"github.com/TIBCOSoftware/flogo-contrib/action/flow/test"
)

var activityMetadata *activity.Metadata

func getActivityMetadata() *activity.Metadata {

	if activityMetadata == nil {
		jsonMetadataBytes, err := ioutil.ReadFile("activity.json")
		if err != nil{
			panic("No Json Metadata found for activity.json path")
		}

		activityMetadata = activity.NewMetadata(string(jsonMetadataBytes))
	}

	return activityMetadata
}

func TestCreate(t *testing.T) {

	act := NewActivity(getActivityMetadata())

	if act == nil {
		t.Error("Activity Not Created")
		t.Fail()
		return
	}
}

func TestEval(t *testing.T) {

	act := NewActivity(getActivityMetadata())
	tc := test.NewTestActivityContext(getActivityMetadata())

	//setup attrs
	tc.SetInput("RdsEndpoint","https://ap-southeast-2.rds.amazonaws.com")
	tc.SetInput("AccessKey","AKIAILBSB7ZYMCQTJHRQ")
	tc.SetInput("SecretKey","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")
	tc.SetInput("DBInstanceIdentifier","flogordsinstance")

	resp,err := act.Eval(tc)
	if(err != nil) {
		fmt.Println("resp:",resp)
	}
	fmt.Println("err ::",err)
	//check result attr
}
