# awsv4signer: aws-sdk-go pluggable request signer

awsv4signer is a fork of the `aws-sdk-go` v4 signer that allows you to provide your own HMAC hasher.
The envisioned use-case for this is to allow you to store your AWS API keys in hardware (a TPM) that
supports HMAC operations.

## Usage

`aws-sdk-go` allows you to replace the request signer on a per service basis.

```
func listBucket(accessKeyID, secretAccessKey, bucket string) {
	s := awsv4signer.Signer{
		AccessKeyID:               accessKeyID,
		SecretAccessKeyHmacSha256: awsv4signer.StaticAccessKeyHmac(secretAccessKey),
	}

	sess := session.New(&aws.Config{
		Region: region,
	})
	svc := s3.New(sess)

	// remove the default v4 signing handler
	svc.Handlers.Sign.RemoveByName(v4.SignRequestHandler.Name)
	// add our signing handler
	svc.Handlers.Sign.PushBack(s.SignSDKRequest)

	resp, err := svc.ListObjects(&s3.ListObjectsInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		panic(err)
	}

	for _, obj := range resp.Contents {
		fmt.Printf("%s\n", *obj.Key)
	}
}
```


## Copyright

Code in internal/awssign is derived from https://github.com/aws/aws-sdk-go. Copyright for that code can be found in NOTICE.txt.
