package main

// import (
// 	"crypto/tls"
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"net/http"
// )

type OpnsenseAPIKey struct {
	key                 string        `yaml:"key"`
	secret                 string        `yaml:"secret"`
}

type OpnsenseAPI struct {
	Name                 string        `yaml:"name"`
	ID                 string        `yaml:"id"`
	Type                 string        `yaml:"type"`
	NetName                 string        `yaml:"network_name"`
	subnetsFormat                 string        `yaml:"subnets_format"`
}

// func setTorAcl() {
//
//
// }
//
//
// func reconfigTor(
// 	apiURL string,
// 	api OpnsenseAPIKey,
// 	retry int,
// ) (map[string]any, error) {
// 	url := fmt.Sprintf("%s/api/unbound/service/reconfigure", apiURL)
//
// 	return reconfig(url, api, retry)
// }


// func reconfig(
// 	apiURL string,
// 	api OpnsenseAPIKey,
// 	retry int,
// ) (map[string]any, error) {
// 	var err error
// 	url := fmt.Sprintf("%s/api/unbound/service/reconfigure", apiURL)
//
//
// 	for range retry {
// 		tr := &http.Transport{
// 			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
// 		}
// 		client := &http.Client{Transport: tr}
//
// 		req, err := http.NewRequest("POST", url, nil)
// 		if err != nil {
// 			err = fmt.Errorf("creating request: %w", err)
// 			continue
// 		}
// 		req.SetBasicAuth(api.key, api.secret)
//
// 		resp, err := client.Do(req)
// 		if err != nil {
// 			err = fmt.Errorf("request error: %w", err)
// 			continue
// 		}
// 		defer resp.Body.Close()
//
// 		body, err := io.ReadAll(resp.Body)
// 		if err != nil {
// 			err = fmt.Errorf("reading body: %w", err)
// 			continue
// 		}
//
// 		if resp.StatusCode != http.StatusOK {
// 			err = fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
// 			continue
// 		}
//
// 		var result map[string]interface{}
// 		if err := json.Unmarshal(body, &result); err != nil {
// 			err = fmt.Errorf("invalid JSON: %w", err)
// 			continue
// 		}
//
// 		fmt.Println("Reconfigure successful!")
// 		fmt.Printf("%+v\n", result)
// 		return result, nil
// 	}
//
// 	return map[string]any{}, err
// }

