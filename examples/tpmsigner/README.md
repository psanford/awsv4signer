# tpmsigner

This is a demo showing how to store an AWS SecretAccessKey in your TPM and then sign requests via the TPM.

## Usage

To load your SecretAccessKey into the TPM and get a key handle back run:

```
$ export SECRET=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
$ ./tpmsigner -store-key-in-tpm $SECRET
wrote: hmac_key_handle

```

Then to use this key to list an s3 bucket:
```
$ ./tpmsigner -accessKeyID AKIAXXXXXXXXXXXXXXXXX -bucket my-personal-bucket
path1/file1
path2/file2
```

## Credits

This example is based on @salrashid123's work in https://github.com/salrashid123/aws_hmac
