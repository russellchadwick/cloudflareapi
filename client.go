package cloudflareapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

const (
	baseURL = "https://api.cloudflare.com/client/v4/"
)

// Client is a cloudflare rest api client
type Client struct {
	AuthEmail          string
	AuthorizationToken string
	Client             *http.Client
}

// NewClient creates a new cloudflare rest api client
// with the given authorization credentials
func NewClient(authEmail string, authorizationToken string) *Client {
	return &Client{
		AuthEmail:          authEmail,
		AuthorizationToken: authorizationToken,
		Client: &http.Client{
			Timeout: time.Second * 5,
		},
	}
}

// ListZones returns all zones associated with the account
func (c *Client) ListZones() ([]ZoneRecord, error) {
	body, err := c.createRequest("zones", nil)
	if err != nil {
		return nil, err
	}

	zoneList := &listZoneRecordsResponse{}
	err = json.Unmarshal(*body, zoneList)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal list zone response: %w", err)
	}

	if !zoneList.Success {
		return nil, fmt.Errorf("failure from cloudflare api: %v", zoneList.Errors)
	}

	return zoneList.Result, nil
}

type listZoneRecordsResponse struct {
	Success bool              `json:"success"`
	Result  []ZoneRecord      `json:"result"`
	Errors  []cloudFlareError `json:"errors"`
}

type cloudFlareError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *cloudFlareError) String() string {
	return fmt.Sprintf("Code=%d Message=%s", e.Code, e.Message)
}

// ZoneRecord is zone from cloudflare api
type ZoneRecord struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ListDNSRecords returns all dns records in a given zone
func (c *Client) ListDNSRecords(zoneID string) ([]DNSRecord, error) {
	body, err := c.createRequest("zones/"+zoneID+"/dns_records", nil)
	if err != nil {
		return nil, err
	}

	dnsList := &listDNSRecordsResponse{}
	err = json.Unmarshal(*body, dnsList)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal list dns records response: %w", err)
	}

	if !dnsList.Success {
		return nil, fmt.Errorf("failure from cloudflare api: %v", dnsList.Errors)
	}

	return dnsList.Result, nil
}

type listDNSRecordsResponse struct {
	Success bool              `json:"success"`
	Result  []DNSRecord       `json:"result"`
	Errors  []cloudFlareError `json:"errors"`
}

// DNSRecord is a dns record from cloudflare api
type DNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

func (dr *DNSRecord) String() string {
	return fmt.Sprintf("ID=%s Type=%s Name=%s Content=%s", dr.ID, dr.Type, dr.Name, dr.Content)
}

// PatchDNSRecord updates the content of the given dns record
func (c *Client) PatchDNSRecord(zoneID string, dnsRecordID string, content string) (*DNSRecord, error) {
	patch := dnsRecordPatch{
		Content: content,
	}
	patchJSON, err := json.Marshal(patch)
	if err != nil {
		return nil, fmt.Errorf("unable to create patch request json: %w", err)
	}

	body, err := c.createRequest("zones/"+zoneID+"/dns_records/"+dnsRecordID, &patchJSON)
	if err != nil {
		return nil, err
	}

	dnsPatch := &patchDNSRecordResponse{}
	err = json.Unmarshal(*body, dnsPatch)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal patch dns record response: %w", err)
	}

	if !dnsPatch.Success {
		return nil, fmt.Errorf("failure from cloudflare api: %v", dnsPatch.Errors)
	}

	return &dnsPatch.Result, nil
}

type dnsRecordPatch struct {
	Content string `json:"content"`
}

type patchDNSRecordResponse struct {
	Success bool              `json:"success"`
	Result  DNSRecord         `json:"result"`
	Errors  []cloudFlareError `json:"errors"`
}

func (c *Client) createRequest(url string, requestBody *[]byte) (*[]byte, error) {
	var method string
	var requestBodyReader io.Reader

	if requestBody == nil {
		method = http.MethodGet
		requestBodyReader = nil
	} else {
		method = http.MethodPatch
		requestBodyReader = bytes.NewReader(*requestBody)
	}
	req, err := http.NewRequest(method, baseURL+url, requestBodyReader)
	if err != nil {
		return nil, fmt.Errorf("unable to create http request: %w", err)
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("X-Auth-Email", c.AuthEmail)
	req.Header.Add("Authorization", "Bearer "+c.AuthorizationToken)
	if requestBody != nil {
		req.Header.Add("Accept", "application/json")
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to get http response: %w", err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, fmt.Errorf("unable to read response: %w", err)
	}

	return &body, nil
}
