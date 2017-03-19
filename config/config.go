// Config is put into a different package to prevent cyclic imports in case
// it is needed in several locations

package config

import (
	"github.com/elastic/beats/libbeat/common"
	"time"
)

type Config struct {
	SSL            SSL            `config:"ssl"`
	Hosts          []string       `config:"hosts" validate:"nonzero,required"`
	Authentication Authentication `config:"authentication"`
	Beans          []Bean         `config:"beans"`
	Period         time.Duration  `config:"period"`
	Combined       bool           `config:"combined"`
}

type SSL struct {
	CAfile string `config:"cafile"`
}

type Authentication struct {
	Username string `config:"username"`
	Password string `config:"password"`
}

type Bean struct {
	Name                 string             `config:"name"`
	Attributes           []Attribute        `config:"attributes"`
	Keys                 []string           `config:"keys"`
	FieldsUnderBean      bool               `config:"fields_under_bean"`
	common.EventMetadata `config:",inline"` // Fields and tags to add to events.

}

type Attribute struct {
	Name string   `config:"name"`
	Keys []string `config:"keys"`
}

var (
	DefaultConfig = Config{
		Period: 10 * time.Second,
		Hosts:  []string{"http://127.0.0.1:8080"},
		Authentication: Authentication{
			Username: "",
			Password: "",
		},
		SSL: SSL{
			CAfile: "",
		},
		Combined: false,
		Beans: []Bean{
			{
				Name: "java.lang:type=Memory",
				Keys: []string{"committed", "init", "max", "used"},
				Attributes: []Attribute{
					{
						Name: "HeapMemoryUsage",
						Keys: []string{},
					}, {
						Name: "NonHeapMemoryUsage",
						Keys: []string{},
					},
				},
				FieldsUnderBean: true,
			},
		},
	}
)
