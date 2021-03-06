package sso

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/workos-inc/workos-go/internal/workos"
)

// ConnectionType represents a connection type.
type ConnectionType string

// Constants that enumerate the available connection types.
const (
	ADFSSAML     ConnectionType = "ADFSSAML"
	AzureSAML    ConnectionType = "AzureSAML"
	GenericSAML  ConnectionType = "GenericSAML"
	GoogleOAuth  ConnectionType = "GoogleOAuth"
	OktaSAML     ConnectionType = "OktaSAML"
	OneLoginSAML ConnectionType = "OneLoginSAML"
	VMwareSAML   ConnectionType = "VMwareSAML"
)

// Client represents a client that fetch SSO data from WorkOS API.
type Client struct {
	// The WorkOS api key. It can be found in
	// https://dashboard.workos.com/api-keys.
	//
	// REQUIRED.
	APIKey string

	// The WorkOS Project ID (eg. project_01JG3BCPTRTSTTWQR4VSHXGWCQ).
	//
	// REQUIRED.
	ProjectID string

	// The callback URL where your app redirects the user-agent after an
	// authorization code is granted (eg. https://foo.com/callback).
	//
	// Deprecated: Use `GetAuthorizationURLOptions.RedirectURI` instead.
	RedirectURI string

	// The endpoint to WorkOS API.
	//
	// Defaults to https://api.workos.com.
	Endpoint string

	// The http.Client that is used to send request to WorkOS.
	//
	// Defaults to http.Client.
	HTTPClient *http.Client

	// The function used to encode in JSON. Defaults to json.Marshal.
	JSONEncode func(v interface{}) ([]byte, error)

	once sync.Once
}

func (c *Client) init() {
	if c.Endpoint == "" {
		c.Endpoint = "https://api.workos.com"
	}
	c.Endpoint = strings.TrimSuffix(c.Endpoint, "/")

	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: time.Second * 15}
	}

	if c.JSONEncode == nil {
		c.JSONEncode = json.Marshal
	}
}

// GetAuthorizationURLOptions contains the options to pass in order to generate
// an authorization url.
type GetAuthorizationURLOptions struct {
	// The app/company domain without without protocol (eg. example.com).
	Domain string

	// Authentication service provider descriptor.
	// Provider is currently only used when the connection type is GoogleOAuth.
	Provider ConnectionType

	// The callback URL where your app redirects the user-agent after an
	// authorization code is granted (eg. https://foo.com/callback).
	//
	// REQUIRED.
	RedirectURI string

	// A unique identifier used to manage state across authorization
	// transactions (eg. 1234zyx).
	//
	// OPTIONAL.
	State string
}

// GetAuthorizationURL returns an authorization url generated with the given
// options.
func (c *Client) GetAuthorizationURL(opts GetAuthorizationURLOptions) (*url.URL, error) {
	c.once.Do(c.init)

	redirectURI := opts.RedirectURI
	if redirectURI == "" {
		redirectURI = c.RedirectURI
	}

	query := make(url.Values, 5)
	query.Set("client_id", c.ProjectID)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")

	if opts.Domain == "" && opts.Provider == "" {
		return nil, errors.New("incomplete arguments: missing domain or provider")
	}
	if opts.Provider != "" {
		query.Set("provider", string(opts.Provider))
	}
	if opts.Domain != "" {
		query.Set("domain", opts.Domain)
	}

	if opts.State != "" {
		query.Set("state", opts.State)
	}

	u, err := url.ParseRequestURI(c.Endpoint + "/sso/authorize")
	if err != nil {
		return nil, err
	}

	u.RawQuery = query.Encode()
	return u, nil
}

// GetProfileOptions contains the options to pass in order to get a user profile.
type GetProfileOptions struct {
	// An opaque string provided by the authorization server. It will be
	// exchanged for an Access Token when the user’s profile is sent.
	Code string
}

// Profile contains information about a user authentication.
type Profile struct {
	// The user ID.
	ID string `json:"id"`

	// An unique alphanumeric identifier for a Profile’s identity provider.
	IdpID string `json:"idp_id"`

	// The connection type.
	ConnectionType ConnectionType `json:"connection_type"`

	// The user email.
	Email string `json:"email"`

	// The user first name. Can be empty.
	FirstName string `json:"first_name"`

	// The user last name. Can be empty.
	LastName string `json:"last_name"`
}

// GetProfile returns a profile describing the user that authenticated with
// WorkOS SSO.
func (c *Client) GetProfile(ctx context.Context, opts GetProfileOptions) (Profile, error) {
	c.once.Do(c.init)

	form := make(url.Values, 5)
	form.Set("client_id", c.ProjectID)
	form.Set("client_secret", c.APIKey)
	form.Set("grant_type", "authorization_code")
	form.Set("code", opts.Code)

	req, err := http.NewRequest(
		http.MethodPost,
		c.Endpoint+"/sso/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return Profile{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Profile{}, err
	}
	defer res.Body.Close()

	if err = workos.TryGetHTTPError(res); err != nil {
		return Profile{}, err
	}

	var body struct {
		Profile     Profile `json:"profile"`
		AccessToken string  `json:"access_token"`
	}
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body.Profile, err
}

// PromoteDraftConnectionOptions contains the options to pass in order to
// promote a draft connection.
type PromoteDraftConnectionOptions struct {
	Token string `json:"token"`
}

// PromoteDraftConnection promotes a draft connection created via the WorkOS.js Embed
// such that the Enterprise users can begin signing into your application.
func (c *Client) PromoteDraftConnection(ctx context.Context, opts PromoteDraftConnectionOptions) error {
	c.once.Do(c.init)

	req, err := http.NewRequest(
		http.MethodPost,
		c.Endpoint+"/draft_connections/"+opts.Token+"/activate",
		nil,
	)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos.TryGetHTTPError(res)
}

// CreateConnectionOpts contains the options to activate a Draft Connection.
type CreateConnectionOpts struct {
	Source string `json:"source"`
}

// ConnectionDomain represents the domain records associated with a Connection.
type ConnectionDomain struct {
	// Connection Domain unique identifier.
	ID string `json:"id"`

	// Domain for a Connection record.
	Domain string `json:"domain"`
}

// ConnectionStatus represents a Connection's linked status.
type ConnectionStatus string

// Constants that enumerate the available Connection's linked statuses.
const (
	Linked   ConnectionStatus = "linked"
	Unlinked ConnectionStatus = "unlinked"
)

// Connection represents a Connection record.
type Connection struct {
	// Connection unique identifier.
	ID string `json:"id"`

	// Connection linked status.
	Status ConnectionStatus `json:"status"`

	// Connection name.
	Name string `json:"name"`

	// Connection provider type.
	ConnectionType ConnectionType `json:"connection_type"`

	// OAuth Client ID.
	OAuthUID string `json:"oauth_uid"`

	// OAuth Client Secret.
	OAuthSecret string `json:"oauth_secret"`

	// OAuth Client Redirect URI.
	OAuthRedirectURI string `json:"oauth_redirect_uri"`

	// Identity Provider Issuer.
	SamlEntityID string `json:"saml_entity_id"`

	// Identity Provider SSO URL.
	SamlIDPURL string `json:"saml_idp_url"`

	// Certificate that describes where to expect valid SAML claims to come from.
	SamlRelyingPartyTrustCert string `json:"saml_relying_party_trust_cert"`

	// Certificates used to authenticate SAML assertions.
	SamlX509Certs []string `json:"saml_x509_certs"`

	// Domain records for the Connection.
	Domains []ConnectionDomain `json:"domains"`
}

// CreateConnection activates a Draft Connection created via the WorkOS.js widget.
func (c *Client) CreateConnection(ctx context.Context, opts CreateConnectionOpts) (Connection, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return Connection{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		c.Endpoint+"/connections",
		bytes.NewBuffer(data),
	)
	if err != nil {
		return Connection{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Connection{}, err
	}
	defer res.Body.Close()

	if err = workos.TryGetHTTPError(res); err != nil {
		return Connection{}, err
	}

	var body Connection
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}
