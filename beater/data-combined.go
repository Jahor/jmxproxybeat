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
						logp.Err("Error requesting '%s//%s//%s' JMX: %v", bean.Name, att.Name, key, err)
						keys[key+"_error"] = err
					} else {
						keys[key] = value
					}
				}
			} else {
				if len(bean.Keys) > 0 {
					for _, key := range bean.Keys {
						value, err := bt.GetJMXObjectValue(u, bean.Name, att.Name, key, bt.config.SSL.CAfile)
						if err != nil {
							logp.Err("Error requesting '%s//%s//%s' JMX: %v", bean.Name, att.Name, key, err)
							keys[key+"_error"] = err
						} else {
							keys[key] = value
						}
					}
				} else {
					value, err := bt.GetJMXObjectValue(u, bean.Name, att.Name, "", bt.config.SSL.CAfile)
					if err != nil {
						logp.Err("Error requesting '%s//%s' JMX: %v", bean.Name, att.Name, err)
						attributes[att.Name+"_error"] = err
					} else {
						attributes[att.Name] = value
					}
				}
			}
			if len(keys) > 0 {
				attributes[att.Name] = keys
			}
		}

		beanDomain, beanParameters := parseBeanName(bean.Name)
		beanType, beanTypeOk := beanParameters["type"]
		var beanDomainType string
		if !beanTypeOk {
			beanDomainType = bean.Name
		} else {
			beanDomainType = beanDomain + "." + beanType.(string)
		}

		beanData := deepMap(beanDomainType, attributes)

		beanData["full_name"] = bean.Name
		beanData["domain"] = beanDomain
		beanData["hostname"] = u.Host

		for k := range beanParameters {
			beanData[k] = beanParameters[k]
		}

		if bean.FieldsUnderBean {
			common.MergeFields(beanData, bean.EventMetadata.Fields, true)
		}

		event := common.MapStr{
			"@timestamp": common.Time(time.Now()),
			"type":       "jmx_combined",
			"bean":       beanData,
		}
		common.AddTags(event, bean.EventMetadata.Tags)
		if !bean.FieldsUnderBean {
			common.MergeFields(event, bean.EventMetadata.Fields, bean.EventMetadata.FieldsUnderRoot)
		}

		bt.client.PublishEvent(event)
		logp.Info("Event: %+v", event)
	}

	return nil
}
func deepMap(name string, content common.MapStr) common.MapStr {
	parts := strings.SplitN(name, ".", 2)

	if len(parts) == 2 {
		return common.MapStr{
			parts[0]: deepMap(parts[1], content),
		}

	}
	return common.MapStr{
		parts[0]: content,
	}
}

func parseBeanName(bean string) (string, common.MapStr) {
	parts := strings.SplitN(bean, ":", 2)

	if len(parts) == 2 {
		domain := parts[0]
		return domain, parseBeanParameters(parts[1])
	}
	return bean, common.MapStr{}
}
func parseBeanParameters(parametersString string) common.MapStr {
	parameters := common.MapStr{}

	start := 0
	it := 0
	for {
		key := ""
		var valueStart int = 0
		for i, c := range parametersString[start:] {
			if c == '=' {
				valueStart = start + i + 1
				break
			} else {
				key += string(c)
			}
		}

		value := ""
		if parametersString[valueStart] == '"' {

			escaped := false
			for i, c := range parametersString[valueStart+1:] {
				if escaped {
					value += string(c)
					escaped = false
				} else {
					if c == '\\' {
						escaped = true
					} else if c == '"' {
						start = valueStart + 1 + i + 2
						break
					} else {
						value += string(c)
					}
				}
			}
		} else {
			finished := false
			for i, c := range parametersString[valueStart:] {
				if c == ',' {
					start = valueStart + i + 1
					finished = true
					break
				} else {
					value += string(c)
				}
			}

			if !finished {
				start = len(parametersString)
			}
		}
		parameters[key] = value

		if start >= len(parametersString) {
			break
		}

		it += 1
		if it > 10 {
			parameters["fail"] = true
			break
		}

	}

	return parameters
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
