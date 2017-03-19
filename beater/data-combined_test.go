package beater

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/elastic/beats/libbeat/common"
)

func TestQuoted(t *testing.T) {
	domain, parameters := parseBeanName("Catalina:type=Resource,resourcetype=Global,class=org.apache.catalina.UserDatabase,name=\"UserDatabase\"")
	assert.EqualValues(t, "Catalina", domain)
	assert.EqualValues(t, common.MapStr{"type": "Resource", "resourcetype": "Global", "class": "org.apache.catalina.UserDatabase", "name": "UserDatabase"}, parameters)
}

func TestSimple(t *testing.T) {
	domain, parameters := parseBeanName("java.lang:type=ClassLoading")
	assert.EqualValues(t, "java.lang", domain)
	assert.EqualValues(t, common.MapStr{"type": "ClassLoading"}, parameters)
}

func TestEscaped(t *testing.T) {
	domain, parameters := parseBeanName("Catalina:type=Resource,resourcetype=Global,class=org.apache.catalina.UserDatabase,name=\"User\\\"Da\\\\tabase\"")
	assert.EqualValues(t, "Catalina", domain)
	assert.EqualValues(t, common.MapStr{"type": "Resource", "resourcetype": "Global", "class": "org.apache.catalina.UserDatabase", "name": "User\"Da\\tabase"}, parameters)
}
