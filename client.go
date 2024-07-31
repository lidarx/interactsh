package client

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/karlseguin/ccache/v3"
	"github.com/lidarx/request"
	"github.com/pkg/errors"
	mathrand "math/rand"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// DeregisterRequest is a request for client deregistration to interactsh server.
type DeregisterRequest struct {
	// CorrelationID is an ID for correlation with requests.
	CorrelationID string `json:"correlation-id"`
	// SecretKey is the secretKey for the interactsh client.
	SecretKey string `json:"secret-key"`
}

// PollResponse is the response for a polling request
type PollResponse struct {
	Data    []string `json:"data"`
	Extra   []string `json:"extra"`
	AESKey  string   `json:"aes_key"`
	TLDData []string `json:"tlddata,omitempty"`
}

// Interaction is an interaction received to the server.
type Interaction struct {
	// Protocol for interaction, can contains HTTP/DNS/SMTP,etc.
	Protocol string `json:"protocol"`
	// UniqueID is the uniqueID for the subdomain receiving the interaction.
	UniqueID string `json:"unique-id"`
	// FullId is the full path for the subdomain receiving the interaction.
	FullId string `json:"full-id"`
	// QType is the question type for the interaction
	QType string `json:"q-type,omitempty"`
	// RawRequest is the raw request received by the interactsh server.
	RawRequest string `json:"raw-request,omitempty"`
	// RawResponse is the raw response sent by the interactsh server.
	RawResponse string `json:"raw-response,omitempty"`
	// SMTPFrom is the mail form field
	SMTPFrom string `json:"smtp-from,omitempty"`
	// RemoteAddress is the remote address for interaction
	RemoteAddress string `json:"remote-address"`
	// Timestamp is the timestamp for the interaction
	Timestamp time.Time           `json:"timestamp"`
	AsnInfo   []map[string]string `json:"asninfo,omitempty"`
}

// RegisterRequest is a request for client registration to interactsh server.
type RegisterRequest struct {
	// PublicKey is the public RSA Key of the client.
	PublicKey string `json:"public-key"`
	// SecretKey is the secret-key for correlation ID registered for the client.
	SecretKey string `json:"secret-key"`
	// CorrelationID is an ID for correlation with requests.
	CorrelationID string `json:"correlation-id"`
}

func init() {
	//todo:automatic with go1.20
	mathrand.Seed(time.Now().UnixNano()) //nolint
}

var authError = errors.New("couldn't authenticate to the server")

type State uint8

const (
	Idle State = iota
	Polling
	Closed
)

// Client is a client for communicating with interactsh server instance.
type Client struct {
	State                    atomic.Value
	correlationID            string
	secretKey                string
	server                   string
	serverUrl                string
	routePrefix              string
	domains                  []string
	domainLength             int
	privKey                  *rsa.PrivateKey
	pubKey                   *rsa.PublicKey
	quitChan                 chan struct{}
	disableHTTPFallback      bool
	token                    string
	correlationIdLength      int
	correlationIdNonceLength int
	cache                    *ccache.Cache[[]*Interaction]
}

// Options contains configuration options for interactsh client
type Options struct {
	// ServerURL is the URL for the interactsh server.
	Server      string
	Domains     []string
	RoutePrefix string
	// Token if the server requires authentication
	Token string
	// CorrelationIdLength of the preamble
	CorrelationIdLength      int
	CorrelationIdNonceLength int
}

// DefaultOptions is the default options for the interact client
var DefaultOptions = &Options{
	CorrelationIdLength:      20,
	CorrelationIdNonceLength: 13,
	RoutePrefix:              "",
}

// New creates a new client instance based on provided options
func New(options *Options) (*Client, error) {
	// if correlation id lengths and nonce are not specified fallback to default:
	if options.CorrelationIdLength == 0 {
		options.CorrelationIdLength = DefaultOptions.CorrelationIdLength
	}
	if options.CorrelationIdNonceLength == 0 {
		options.CorrelationIdNonceLength = DefaultOptions.CorrelationIdNonceLength
	}

	var correlationID, secretKey, token string

	correlationID = RandString(options.CorrelationIdLength)
	secretKey = RandString(8)
	token = options.Token

	client := &Client{
		secretKey:                secretKey,
		correlationID:            correlationID,
		token:                    token,
		correlationIdLength:      options.CorrelationIdLength,
		correlationIdNonceLength: options.CorrelationIdNonceLength,
		domains:                  options.Domains,
		domainLength:             len(options.Domains),
		routePrefix:              options.RoutePrefix,
	}

	payload, err := client.initializeRSAKeys()
	if err != nil {
		return nil, errors.Wrap(err, "could not initialize rsa keys")
	}

	if err := client.parseServerURLs(options.Domains, options.Server, payload); err != nil {
		return nil, errors.Wrap(err, "could not register to servers")
	}

	client.cache = ccache.New[[]*Interaction](ccache.Configure[[]*Interaction]().MaxSize(10240))

	return client, nil
}

// initializeRSAKeys does the one-time initialization for RSA crypto mechanism
// and returns the data payload for the client.
func (c *Client) initializeRSAKeys() (string, error) {
	// Generate a 2048-bit private-key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", errors.Wrap(err, "could not generate rsa private key")
	}
	c.privKey = priv
	c.pubKey = &priv.PublicKey

	pubKeyData, err := encodePublicKey(c.pubKey)
	if err != nil {
		return "", err
	}

	return encodeRegistrationRequest(pubKeyData, c.secretKey, c.correlationID)
}

func (c *Client) Get(fullID string) ([]*Interaction, error) {
	if c.cache.Get(fullID) != nil {
		return c.cache.Get(fullID).Value(), nil
	} else {
		// GET
		err := c.getInteractions(func(interaction *Interaction) {})
		if err != nil {
			return nil, err
		}
	}
	if c.cache.Get(fullID) != nil {
		return c.cache.Get(fullID).Value(), nil
	} else {
		return nil, nil
	}
}

func encodeRegistrationRequest(publicKey, secretkey, correlationID string) (string, error) {
	register := RegisterRequest{
		PublicKey:     publicKey,
		SecretKey:     secretkey,
		CorrelationID: correlationID,
	}

	data, err := json.Marshal(register)
	if err != nil {
		return "", errors.Wrap(err, "could not marshal register request")
	}
	return string(data), nil
}

func encodePublicKey(pubKey *rsa.PublicKey) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", errors.Wrap(err, "could not marshal public key")
	}
	pubkeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubkeyBytes,
	})

	encoded := base64.StdEncoding.EncodeToString(pubkeyPem)
	return encoded, nil
}

func decodePublicKey(data string) (*rsa.PublicKey, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	pubkeyPem, _ := pem.Decode(decodedBytes)

	pubKey, err := x509.ParsePKIXPublicKey(pubkeyPem.Bytes)
	if err != nil {
		return nil, err
	}

	if rsaPubKey, ok := pubKey.(*rsa.PublicKey); ok {
		return rsaPubKey, nil
	}

	return nil, errors.New("unsupported public key")
}

// parseServerURLs parses server url string. Multiple URLs are supported
// comma separated and a random one will be used on runtime.
//
// If the https scheme is not working, http is tried. url can be comma separated
// domains or full urls as well.
//
// If the first picked random domain doesn't work, the list of domains is iterated
// after being shuffled.
func (c *Client) parseServerURLs(domains []string, serverIP string, payload string) error {
	if len(domains) == 0 {
		return errors.New("invalid server url provided")
	}

	var server string
	if serverIP != "" {
		server = serverIP
	} else {
		firstIdx := mathrand.Intn(len(domains))
		ips, err := net.LookupIP(domains[firstIdx])
		if err != nil || len(ips) == 0 {
			return errors.Wrap(err, "could not lookup server with domain "+domains[firstIdx])
		}
		server = ips[0].String()
	}
	if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
		server = fmt.Sprintf("https://%s", server)
	}
	parsed, err := url.Parse(server)
	if err != nil {
		return errors.Wrap(err, "could not parse server URL")
	}
	req, resp := request.AcquireRequestResponse()
	err = req.Get(parsed.String()).Do(resp)
	if err != nil {
		parsed.Scheme = "http"
		err = req.Get(parsed.String()).Do(resp)
		if err != nil {
			return errors.Wrap(err, "could not connect to server")
		}
	}
	if err := c.performRegistration(parsed.String(), payload); err != nil {
		return err
	}
	c.serverUrl = parsed.String()
	return nil
}

func removeIndex(s []string, index int) []string {
	return append(s[:index], s[index+1:]...)
}

func (c *Client) Poll(callback InteractionCallback, afterPolling func()) error {
	err := c.getInteractions(callback)
	if err != nil {
		return err
	} else {
		afterPolling()
		return nil
	}
}

// InteractionCallback is a callback function for a reported interaction
type InteractionCallback func(*Interaction)

// StartPolling starts polling the server each duration and returns any events
// that may have been captured by the collaborator server.
func (c *Client) StartPolling(duration time.Duration, callback InteractionCallback, afterPolling func()) error {
	switch c.State.Load() {
	case Polling:
		return errors.New("client is already polling")
	case Closed:
		return errors.New("client is closed")
	}

	c.State.Store(Polling)

	ticker := time.NewTicker(duration)
	c.quitChan = make(chan struct{})
	go func() {
		for {
			// exit if the client is not polling
			if c.State.Load() != Polling {
				return
			}
			select {
			case <-ticker.C:
				if err := c.Poll(callback, afterPolling); err != nil {
					fmt.Println("error polling:", err)
				}
			case <-c.quitChan:
				ticker.Stop()
				return
			}
		}
	}()

	return nil
}

// getInteractions returns the interactions from the server.
func (c *Client) getInteractions(callback InteractionCallback) error {
	req, resp := request.AcquireRequestResponse()
	defer request.ReleaseRequestResponse(req, resp)
	if c.token != "" {
		req.SetHeader(request.Header{"Authorization": c.token})
	}
	err := req.Get(c.serverUrl+c.routePrefix+"/poll", request.Params{"id": c.correlationID, "secret": c.secretKey}).Do(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		if resp.StatusCode() == 401 {
			return authError
		}
		if strings.Contains(resp.Text(), "could not get correlation-id from cache") {
			return errors.New("could not get correlation-id from cache")
		}
		return fmt.Errorf("could not poll interactions: %s", resp.Text())
	}
	response := &PollResponse{}
	if err := json.Unmarshal(resp.Body(), response); err != nil {
		return errors.Wrap(err, "Could not decode interactions")
	}

	for _, data := range response.Data {
		plaintext, err := c.decryptMessage(response.AESKey, data)
		if err != nil {
			fmt.Println("error decrypting interaction:", err)
			continue
		}
		interaction := &Interaction{}
		if err := json.Unmarshal(plaintext, interaction); err != nil {
			fmt.Println("error unmarshaling interaction:", err)
			continue
		}
		if c.cache.Get(interaction.FullId) != nil {
			interactions := c.cache.Get(interaction.FullId).Value()
			interactions = append(interactions, interaction)
			c.cache.Set(interaction.FullId, interactions, time.Second*60)
		} else {
			c.cache.Set(interaction.FullId, []*Interaction{interaction}, time.Second*60)
		}
		callback(interaction)
	}

	for _, plaintext := range response.Extra {
		interaction := &Interaction{}
		if err := json.Unmarshal([]byte(plaintext), interaction); err != nil {
			fmt.Println("error unmarshaling interaction:", err)
			continue
		}
		callback(interaction)
	}

	// handle root-tld data if any
	for _, data := range response.TLDData {
		interaction := &Interaction{}
		if err := json.Unmarshal([]byte(data), interaction); err != nil {
			fmt.Println("error unmarshaling interaction:", err)
			continue
		}
		callback(interaction)
	}

	return nil
}

func (c *Client) GetDomain() string {
	return c.correlationID + RandString(c.correlationIdNonceLength) + "." + c.domains[mathrand.Intn(c.domainLength)]
}

// StopPolling stops the polling to the interactsh server.
func (c *Client) StopPolling() error {
	if c.State.Load() != Polling {
		return errors.New("client is not polling")
	}
	close(c.quitChan)

	c.State.Store(Idle)

	return nil
}

// Close closes the collaborator client and deregisters from the
// collaborator server if not explicitly asked by the user.
func (c *Client) Close() error {
	if c.State.Load() == Polling {
		return errors.New("client should stop polling before closing")
	}
	if c.State.Load() == Closed {
		return errors.New("client is already closed")
	}

	register := DeregisterRequest{
		CorrelationID: c.correlationID,
		SecretKey:     c.secretKey,
	}
	data, err := json.Marshal(register)
	if err != nil {
		return errors.Wrap(err, "could not marshal deregister request")
	}
	req, resp := request.AcquireRequestResponse()
	defer request.ReleaseRequestResponse(req, resp)
	if c.token != "" {
		req.Header.Add("Authorization", c.token)
	}
	err = req.Post(c.serverUrl+c.routePrefix+"/deregister", data).Do(resp)
	if err != nil {
		return errors.Wrap(err, "could not make deregister request")
	}
	if resp.StatusCode() != 200 {
		return fmt.Errorf("could not deregister to server: %s", resp.Text())
	}
	c.State.Store(Closed)
	return nil
}

// performRegistration registers the current client with the master server using the
// provided RSA Public Key as well as Correlation Key.
func (c *Client) performRegistration(serverURL string, payload string) error {
	req, resp := request.AcquireRequestResponse()
	defer request.ReleaseRequestResponse(req, resp)
	if c.token != "" {
		req.SetHeader(request.Header{"Authorization": c.token})
	}
	err := req.Post(serverURL+c.routePrefix+"register", payload).Do(resp)
	if err != nil {
		return errors.Wrap(err, "could not make register request")
	}
	if resp.StatusCode() == 401 {
		return errors.New("invalid token provided for interactsh server")
	}
	if resp.StatusCode() != 200 {
		return fmt.Errorf("could not register to server: %s", resp.String())
	}
	response := make(map[string]interface{})
	err = json.Unmarshal(resp.Body(), &response)
	if err != nil {
		return errors.Wrap(err, "could not unmarshal register response")
	}
	message, ok := response["message"]
	if !ok {
		return errors.New("could not get register response")
	}
	if message.(string) != "registration successful" {
		return fmt.Errorf("could not get register response: %s", message.(string))
	}
	c.State.Store(Idle)
	return nil
}

// decryptMessage decrypts an AES-256-RSA-OAEP encrypted message to string
func (c *Client) decryptMessage(key string, secureMessage string) ([]byte, error) {
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	// Decrypt the key plaintext first
	keyPlaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.privKey, decodedKey, nil)
	if err != nil {
		return nil, err
	}

	cipherText, err := base64.StdEncoding.DecodeString(secureMessage)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(keyPlaintext)
	if err != nil {
		return nil, err
	}

	if len(cipherText) < aes.BlockSize {
		return nil, errors.New("ciphertext block size is too small")
	}

	// IV is at the start of the Ciphertext
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	// XORKeyStream can work in-place if the two arguments are the same.
	stream := cipher.NewCFBDecrypter(block, iv)
	decoded := make([]byte, len(cipherText))
	stream.XORKeyStream(decoded, cipherText)
	return decoded, nil
}

func RandString(length int) string {
	letters := []rune("0123456789abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[mathrand.Intn(len(letters))]
	}
	return string(b)
}
