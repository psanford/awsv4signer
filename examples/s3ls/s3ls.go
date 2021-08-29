package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/psanford/awsv4signer"
)

var (
	accessKeyID     = flag.String("accessKeyID", "", "AWS Access Key ID")
	secretAccessKey = flag.String("secretAccessKey", "", "Secret Access Key")
	bucket          = flag.String("bucket", "", "Bucket to list")
	region          = flag.String("region", "us-east-1", "AWS Region")
)

func main() {
	flag.Parse()

	if *accessKeyID == "" || *secretAccessKey == "" || *bucket == "" {
		log.Fatal("-accessKeyID -secretAccessKey and -bucket are required")
		flag.Usage()
	}

	listBucket(*accessKeyID, *secretAccessKey, *bucket)
}

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
