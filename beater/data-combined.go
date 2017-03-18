package beater

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"strings"
)

func (bt *Jmxproxybeat) GetJMXCombined(u url.URL) error {

	for _, bean := range bt.config.Beans {

		attributes := common.MapStr{}
		for _, att := range bean.Attributes {
			keys := common.MapStr{}
			if len(att.Keys) > 0 {
				for _, key := range att.Keys {
					value, err := bt.GetJMXObjectValue(u, bean.Name, att.Name, key, bt.config.SSL.CAfile)
					if err != nil {
						logp.Err("Error requesting JMX: %v", err)
						keys[key] = err
					} else {
						keys[key] = value
					}
				}
			} else {
				if len(bean.Keys) > 0 {
					for _, key := range bean.Keys {
						value, err := bt.GetJMXObjectValue(u, bean.Name, att.Name, key, bt.config.SSL.CAfile)
						if err != nil {
							logp.Err("Error requesting JMX: %v", err)
							keys[key] = err
						} else {
							keys[key] = value
						}
					}
				} else {
					value, err := bt.GetJMXObjectValue(u, bean.Name, att.Name, "", bt.config.SSL.CAfile)
					if err != nil {
						logp.Err("Error requesting JMX: %v", err)
						attributes[att.Name] = err
					} else {
						attributes[att.Name] = value
					}
				}
			}
			if len(keys) > 0 {
				attributes[att.Name] = keys
			}
		}

		event := common.MapStr{
			"@timestamp": common.Time(time.Now()),
			"type":       "jmx",
			"bean": common.MapStr{
				"name":     bean.Name,
				"hostname": u.Host,
				strings.Replace(bean.Name, ".", "/", -1): attributes,
			},
		}
		bt.client.PublishEvent(event)
		logp.Info("Event: %+v", event)
	}

	return nil
}

func (bt *Jmxproxybeat) GetJMXObjectValue(u url.URL, name, attribute, key string, CAFile string) (float64, error) {

	tlsConfig := &tls.Config{RootCAs: x509.NewCertPool()}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	var ParsedUrl *url.URL

	if CAFile != "" {
		// Load our trusted certificate path
		pemData, err := ioutil.ReadFile(CAFile)
		if err != nil {
			panic(err)
		}
		ok := tlsConfig.RootCAs.AppendCertsFromPEM(pemData)
		if !ok {
			logp.Err("Unable to load CA file")
			panic("Couldn't load PEM data")
		}
	}

	//client := &http.Client{}
	client := &http.Client{Transport: transport}

	ParsedUrl, err := url.Parse(u.String())
	if err != nil {
		logp.Err("Unable to parse URL String")
		panic(err)
	}

	ParsedUrl.Path += managerJmxproxy
	parameters := url.Values{}

	parameters.Add("get", name)

	//var jmxObject,
	if key != "" {
		//jmxObject = name + attributeURI + attribute + keyURI + key
		parameters.Add("att", attribute)
		parameters.Add("key", key)
	} else {
		//jmxObject = name + attributeURI + attribute
		parameters.Add("att", attribute)
	}

	ParsedUrl.RawQuery = parameters.Encode()

	logp.Debug(selector, "Requesting JMX: %s", ParsedUrl.String())

	req, err := http.NewRequest("GET", ParsedUrl.String(), nil)

	if bt.auth {
		req.SetBasicAuth(bt.config.Authentication.Username, bt.config.Authentication.Password)
	}
	res, err := client.Do(req)

	if err != nil {
		return 0.0, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return 0.0, fmt.Errorf("HTTP %s", res.Status)
	}

	scanner := bufio.NewScanner(res.Body)
	scanner.Scan()

	jmxValue, err := GetJMXValue(scanner.Text())
	if err != nil {
		return 0.0, err
	}

	return jmxValue, nil
}
