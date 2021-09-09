package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/psanford/awsv4signer"
)

var (
	storeKeyInTPM = flag.String("store-key-in-tpm", "", "Store provided key in the TPM and have the handle to -hmackKeyHandle")
	tpmPath       = flag.String("tpmPath", "/dev/tpmrm0", "TPM Device Path")
	flush         = flag.String("flush", "all", "Data to HMAC")
	hmacKeyHandle = flag.String("hmacKeyHandle", "hmac_key_handle", "Handle to the primary")

	accessKeyID = flag.String("accessKeyID", "", "AWS Access Key ID")
	bucket      = flag.String("bucket", "", "Bucket to list")
	region      = flag.String("region", "us-east-1", "AWS Region")

	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient, tpm2.HandleTypeHMACSession},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
	}

	primaryKeyParams = tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagRestricted | tpm2.FlagDecrypt |
			tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			CurveID: tpm2.CurveNISTP256,
		},
	}
)

const (
	emptyPassword                   = ""
	defaultPassword                 = ""
	CmdHmacStart    tpmutil.Command = 0x0000015B
)

func main() {
	flag.Parse()

	if *storeKeyInTPM != "" {
		err := storeKey()
		if err != nil {
			log.Fatal(err)
		}
	} else if *accessKeyID != "" && *bucket != "" {
		err := listBucket()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Printf("use -store-key-in-tpm to save key to tpm")
		log.Printf("use -accessKeyID and -bucket to list files in bucket using TPM for signing")
		flag.Usage()
	}
}

func storeKey() error {
	secretAccessKey := *storeKeyInTPM

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return fmt.Errorf("Open tpm err: %w", err)
	}
	defer rwc.Close()

	for _, handleType := range handleNames[*flush] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			return fmt.Errorf("get handle err: %w", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				return fmt.Errorf("flush handle err: %w", err)
			}
		}
	}

	pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, emptyPassword, emptyPassword, primaryKeyParams)
	if err != nil {
		return fmt.Errorf("CreatePrimary err: %w", err)
	}
	defer tpm2.FlushContext(rwc, pkh)

	public := tpm2.Public{
		Type:       tpm2.AlgKeyedHash,
		NameAlg:    tpm2.AlgSHA256,
		AuthPolicy: []byte(defaultPassword),
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagUserWithAuth | tpm2.FlagSign,
		KeyedHashParameters: &tpm2.KeyedHashParams{
			Alg:  tpm2.AlgHMAC,
			Hash: tpm2.AlgSHA256,
		},
	}
	hmacKeyBytes := []byte("AWS4" + secretAccessKey)
	privInternal, pubArea, _, _, _, err := tpm2.CreateKeyWithSensitive(rwc, pkh, tpm2.PCRSelection{}, defaultPassword, defaultPassword, public, hmacKeyBytes)
	if err != nil {
		return fmt.Errorf("CreateKeyWithSensitive err: %w", err)
	}

	k := keyHandle{
		Pub:  pubArea,
		Priv: privInternal,
	}

	ekhBytes, err := json.Marshal(k)
	if err != nil {
		return fmt.Errorf("marshal wrapped key err: %s", err)
	}

	err = ioutil.WriteFile(*hmacKeyHandle, ekhBytes, 0600)
	if err != nil {
		return fmt.Errorf("write key err: %w", err)
	}

	fmt.Printf("wrote: %s\n", *hmacKeyHandle)

	return nil
}

func listBucket() error {
	ekhBytes, err := ioutil.ReadFile(*hmacKeyHandle)
	if err != nil {
		return fmt.Errorf("failed to read hmacKeyHandle file: %w", err)
	}

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return fmt.Errorf("Open tpm err: %w", err)
	}
	defer rwc.Close()

	for _, handleType := range handleNames[*flush] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			return fmt.Errorf("get handle err: %w", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				return fmt.Errorf("flush handle err: %w", err)
			}
		}
	}

	var k keyHandle
	err = json.Unmarshal(ekhBytes, &k)
	if err != nil {
		return fmt.Errorf("unmarshal hmac-handle err: %w", err)
	}

	pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, emptyPassword, emptyPassword, primaryKeyParams)
	if err != nil {
		return fmt.Errorf("CreatePrimary err: %w", err)
	}
	defer tpm2.FlushContext(rwc, pkh)

	hmacHandle, _, err := tpm2.Load(rwc, pkh, emptyPassword, k.Pub, k.Priv)
	if err != nil {
		return fmt.Errorf("load hash key err: %w", err)
	}

	tpm := tpm{
		tpm: rwc,
	}

	s := awsv4signer.Signer{
		AccessKeyID: *accessKeyID,
		SecretAccessKeyHmacSha256: func() hash.Hash {
			return &TpmHmac{
				tpm:    &tpm,
				handle: hmacHandle,
			}
		},
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
		Bucket: bucket,
	})
	if err != nil {
		panic(err)
	}

	for _, obj := range resp.Contents {
		fmt.Printf("%s\n", *obj.Key)
	}

	return nil
}

func encodeAuthArea(sections ...tpm2.AuthCommand) ([]byte, error) {
	var res tpmutil.RawBytes
	for _, s := range sections {
		buf, err := tpmutil.Pack(s)
		if err != nil {
			return nil, err
		}
		res = append(res, buf...)
	}

	size, err := tpmutil.Pack(uint32(len(res)))
	if err != nil {
		return nil, err
	}

	return concat(size, res)
}

type TpmHmac struct {
	tpm    *tpm
	handle tpmutil.Handle
	buf    bytes.Buffer
}

func (h *TpmHmac) Write(b []byte) (int, error) {
	return h.buf.Write(b)
}

func (h *TpmHmac) Sum(b []byte) []byte {
	msg, err := h.tpm.HmacMsg(h.handle, h.buf.Bytes())
	if err != nil {
		panic(err)
	}
	if b != nil {
		b = append(b, msg...)
		return b
	}
	return msg
}

func (h *TpmHmac) Size() int {
	return sha256.Size
}

func (h *TpmHmac) BlockSize() int {
	return sha256.BlockSize
}

func (h *TpmHmac) Reset() {
	h.buf.Reset()
}

type tpm struct {
	mu  sync.Mutex
	tpm io.ReadWriteCloser
}

func (t *tpm) HmacMsg(handle tpmutil.Handle, msg []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	seqAuth := ""
	seq, err := t.hmacStart(seqAuth, handle, tpm2.AlgSHA256)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(t.tpm, seq)

	maxDigestBuffer := 1024
	for len(msg) > maxDigestBuffer {
		if err = tpm2.SequenceUpdate(t.tpm, seqAuth, seq, msg[:maxDigestBuffer]); err != nil {
			return nil, err
		}
		msg = msg[maxDigestBuffer:]
	}

	digest, _, err := tpm2.SequenceComplete(t.tpm, seqAuth, seq, tpm2.HandleNull, msg)
	if err != nil {
		return nil, err
	}

	return digest, nil
}

func (t *tpm) hmacStart(sequenceAuth string, handle tpmutil.Handle, hashAlg tpm2.Algorithm) (seqHandle tpmutil.Handle, err error) {

	auth, err := encodeAuthArea(tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession, Auth: []byte(sequenceAuth)})
	if err != nil {
		return 0, err
	}
	out, err := tpmutil.Pack(handle)
	if err != nil {
		return 0, err
	}
	Cmd, err := concat(out, auth)
	if err != nil {
		return 0, err
	}

	resp, err := runCommand(t.tpm, tpm2.TagSessions, CmdHmacStart, tpmutil.RawBytes(Cmd), tpmutil.U16Bytes(sequenceAuth), hashAlg)
	if err != nil {
		return 0, err
	}
	var rhandle tpmutil.Handle
	_, err = tpmutil.Unpack(resp, &rhandle)
	return rhandle, err
}

func runCommand(rw io.ReadWriter, tag tpmutil.Tag, Cmd tpmutil.Command, in ...interface{}) ([]byte, error) {
	resp, code, err := tpmutil.RunCommand(rw, tag, Cmd, in...)
	if err != nil {
		return nil, err
	}
	if code != tpmutil.RCSuccess {
		return nil, decodeResponse(code)
	}
	return resp, decodeResponse(code)
}

func concat(chunks ...[]byte) ([]byte, error) {
	return bytes.Join(chunks, nil), nil
}

func decodeResponse(code tpmutil.ResponseCode) error {
	if code == tpmutil.RCSuccess {
		return nil
	}
	if code&0x180 == 0 { // Bits 7:8 == 0 is a TPM1 error
		return fmt.Errorf("response status 0x%x", code)
	}
	if code&0x80 == 0 { // Bit 7 unset
		if code&0x400 > 0 { // Bit 10 set, vendor specific code
			return tpm2.VendorError{Code: uint32(code)}
		}
		if code&0x800 > 0 { // Bit 11 set, warning with code in bit 0:6
			return tpm2.Warning{Code: tpm2.RCWarn(code & 0x7f)}
		}
		// error with code in bit 0:6
		return tpm2.Error{Code: tpm2.RCFmt0(code & 0x7f)}
	}
	if code&0x40 > 0 { // Bit 6 set, code in 0:5, parameter number in 8:11
		return tpm2.ParameterError{Code: tpm2.RCFmt1(code & 0x3f), Parameter: tpm2.RCIndex((code & 0xf00) >> 8)}
	}
	if code&0x800 == 0 { // Bit 11 unset, code in 0:5, handle in 8:10
		return tpm2.HandleError{Code: tpm2.RCFmt1(code & 0x3f), Handle: tpm2.RCIndex((code & 0x700) >> 8)}
	}
	// Code in 0:5, Session in 8:10
	return tpm2.SessionError{Code: tpm2.RCFmt1(code & 0x3f), Session: tpm2.RCIndex((code & 0x700) >> 8)}
}

type keyHandle struct {
	Pub  []byte `json:"pub"`
	Priv []byte `json:"priv"`
}
