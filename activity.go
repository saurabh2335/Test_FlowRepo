package describedbinstance

import (
	"github.com/TIBCOSoftware/flogo-lib/core/activity"
	"github.com/TIBCOSoftware/flogo-lib/logger"
	"time"
	"net/url"
	"encoding/xml"
	"encoding/base64"
	"net/http"
	"sort"
	"strings"
	"crypto/hmac"
	"crypto/sha256"
	"strconv"
)


var log = logger.GetLogger("activity-tibco-rds")

var b64 = base64.StdEncoding
var unreserved = make([]bool, 128)
var hex = "0123456789ABCDEF"
const APIVersion = "2014-10-31"

const (
	ivRdsEndpoint 		  =      "RdsEndpoint"
	ivAccessKey  		  =		 "AccessKey"
	ivSecretKey  		  =		 "SecretKey"
	ivDBInstanceIdentifier =   	 "DBInstanceIdentifier"

	ovresponse = "Response"
)

type SimpleResp struct {
	RequestId string `xml:"ResponseMetadata>RequestId"`
}

type xmlErrors struct {
	Errors []Error `xml:"Error"`
}

// Error encapsulates an Rds error.
type Error struct {
	// HTTP status code of the error.
	StatusCode int

	// AWS code of the error.
	Code string

	// Message explaining the error.
	Message string
}

type DBInstance struct {
	Address                    string        `xml:"Endpoint>Address"`
	AllocatedStorage           int           `xml:"AllocatedStorage"`
	StorageType                string        `xml:"StorageType"`
	AvailabilityZone           string        `xml:"AvailabilityZone"`
	BackupRetentionPeriod      int           `xml:"BackupRetentionPeriod"`
	DBInstanceClass            string        `xml:"DBInstanceClass"`
	DBInstanceIdentifier       string        `xml:"DBInstanceIdentifier"`
	DBInstanceStatus           string        `xml:"DBInstanceStatus"`
	DBName                     string        `xml:"DBName"`
	Engine                     string        `xml:"Engine"`
	EngineVersion              string        `xml:"EngineVersion"`
	StorageEncrypted           bool          `xml:"StorageEncrypted"`
	MasterUsername             string        `xml:"MasterUsername"`
	MultiAZ                    bool          `xml:"MultiAZ"`
	Port                       int           `xml:"Endpoint>Port"`
	PreferredBackupWindow      string        `xml:"PreferredBackupWindow"`
	PreferredMaintenanceWindow string        `xml:"PreferredMaintenanceWindow"`
	VpcSecurityGroupIds        []string      `xml:"VpcSecurityGroups>VpcSecurityGroupMembership>VpcSecurityGroupId"`
	DBSecurityGroupNames       []string      `xml:"DBSecurityGroups>DBSecurityGroup>DBSecurityGroupName"`
	DBParameterGroupName       string        `xml:"DBParameterGroups>DBParameterGroup>DBParameterGroupName"`
}

// DescribeDBInstances request params

type DescribeDBInstancesResp struct {
	RequestId   string       `xml:"ResponseMetadata>RequestId"`
	DBInstances []DBInstance `xml:"DescribeDBInstancesResult>DBInstances>DBInstance"`
}


// MyActivity is a stub for your Activity implementation
type MyActivity struct {
	metadata *activity.Metadata
}

// NewActivity creates a new activity
func NewActivity(metadata *activity.Metadata) activity.Activity {
	return &MyActivity{metadata: metadata}
}

// Metadata implements activity.Activity.Metadata
func (a *MyActivity) Metadata() *activity.Metadata {
	return a.metadata
}

// Eval implements activity.Activity.Eval
func (a *MyActivity) Eval(context activity.Context) (done bool, err error)  {

	// do eval
	params := make(map[string]string)
	params["Action"] = "DescribeDBInstances"

	params["DBInstanceIdentifier"] = context.GetInput(ivDBInstanceIdentifier).(string)

	resp := &DescribeDBInstancesResp{}

	RdsEndpoint := context.GetInput(ivRdsEndpoint).(string)
	AccessKey := context.GetInput(ivAccessKey).(string)
	SecretKey := context.GetInput(ivSecretKey).(string)

	err = query(params, RdsEndpoint, AccessKey, SecretKey, resp)

	if err != nil {
		resp = nil
	}

	return true, nil
}
func query(params map[string]string, RdsEndpoint string, AccessKey string, SecretKey string, resp interface{}) error {
	params["Version"] = APIVersion
	params["Timestamp"] = time.Now().In(time.UTC).Format(time.RFC3339)

	httpClient := http.Client{}
	endpoint, err := url.Parse(RdsEndpoint)
	if err != nil {
		return err
	}

	sign(AccessKey, SecretKey, "GET", "/", params, endpoint.Host)
	endpoint.RawQuery = multimap(params).Encode()
	r, err := httpClient.Get(endpoint.String())

	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode > 200 {
		return buildError(r)
	}

	decoder := xml.NewDecoder(r.Body)
	decodedBody := decoder.Decode(resp)

	return decodedBody
}
func multimap(p map[string]string) url.Values {
	q := make(url.Values, len(p))
	for k, v := range p {
		q[k] = []string{v}
	}
	return q
}
func Encode(s string) string {
	encode := false
	for i := 0; i != len(s); i++ {
		c := s[i]
		if c > 127 || !unreserved[c] {
			encode = true
			break
		}
	}
	if !encode {
		return s
	}
	e := make([]byte, len(s)*3)
	ei := 0
	for i := 0; i != len(s); i++ {
		c := s[i]
		if c > 127 || !unreserved[c] {
			e[ei] = '%'
			e[ei+1] = hex[c>>4]
			e[ei+2] = hex[c&0xF]
			ei += 3
		} else {
			e[ei] = c
			ei += 1
		}
	}
	return string(e[:ei])
}
func sign(AccessKey string, SecretKey string, method, path string, params map[string]string, host string) {
	params["AWSAccessKeyId"] = AccessKey
	params["SignatureVersion"] = "2"
	params["SignatureMethod"] = "HmacSHA256"

	var sarray []string
	for k, v := range params {
		sarray = append(sarray, Encode(k)+"="+Encode(v))
	}
	sort.StringSlice(sarray).Sort()
	joined := strings.Join(sarray, "&")
	payload := method + "\n" + host + "\n" + path + "\n" + joined
	hash := hmac.New(sha256.New, []byte(SecretKey))
	hash.Write([]byte(payload))
	signature := make([]byte, b64.EncodedLen(hash.Size()))
	b64.Encode(signature, hash.Sum(nil))

	params["Signature"] = string(signature)
}
func buildError (r *http.Response) error {
	var (
		err    Error
		errors xmlErrors
	)
	xml.NewDecoder(r.Body).Decode(&errors)
	if len(errors.Errors) > 0 {
		err = errors.Errors[0]
	}
	err.StatusCode = r.StatusCode
	if err.Message == "" {
		err.Message = r.Status
	}
	return &err
}

func (e *Error) Error() string {
	var prefix string
	if e.Code != "" {
		prefix = e.Code + ": "
	}
	if prefix == "" && e.StatusCode > 0 {
		prefix = strconv.Itoa(e.StatusCode) + ": "
	}
	return prefix + e.Message
}
