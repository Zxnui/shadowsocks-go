/**
 * Created with IntelliJ IDEA.
 * User: clowwindy
 * Date: 12-11-2
 * Time: 上午10:31
 * To change this template use File | Settings | File Templates.
 */
package shadowsocks

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	// "log"
	"os"
	"reflect"
	"strings"
	"time"
)

type Config struct {
	Server     interface{} `json:"server"`
	ServerPort int         `json:"server_port"`
	LocalPort  int         `json:"local_port"`
	Password   string      `json:"password"`
	Method     string      `json:"method"` // encryption method
	Auth       bool        `json:"auth"`   // one time auth

	// following options are only used by server
	PortPassword map[string]string `json:"port_password"`
	Timeout      int               `json:"timeout"`

	// following options are only used by client

	// The order of servers in the client config is significant, so use array
	// instead of map to preserve the order.
	ServerPassword [][]string `json:"server_password"`
}

//配置文件中，超时时间
var readTimeout time.Duration

func (config *Config) GetServerArray() []string {
	// Specifying multiple servers in the "server" options is deprecated.
	// But for backward compatiblity, keep this.
	if config.Server == nil {
		return nil
	}
	single, ok := config.Server.(string)
	if ok {
		return []string{single}
	}
	arr, ok := config.Server.([]interface{})
	if ok {
		/*
			if len(arr) > 1 {
				log.Println("Multiple servers in \"server\" option is deprecated. " +
					"Please use \"server_password\" instead.")
			}
		*/
		serverArr := make([]string, len(arr), len(arr))
		for i, s := range arr {
			serverArr[i], ok = s.(string)
			if !ok {
				goto typeError
			}
		}
		return serverArr
	}
typeError:
	panic(fmt.Sprintf("Config.Server type error %v", reflect.TypeOf(config.Server)))
}

//配置文件，解析到config结构中
func ParseConfig(path string) (config *Config, err error) {
	file, err := os.Open(path) // 读取配置文件
	if err != nil {
		return
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file) //从文件中读取，直至遇到错误或EOF，然后返回它所读取的数据
	if err != nil {
		return
	}

	config = &Config{}
	if err = json.Unmarshal(data, config); err != nil { //配置文件是json格式的数据，解析配置文件的值，结果存储到config中
		return nil, err
	}
	readTimeout = time.Duration(config.Timeout) * time.Second //读取配置文件中超时时间

	//加密方法，后缀-auth的情况，需要加密
	//server之前好像已经处理过了，为何还在在处理一次？
	if strings.HasSuffix(strings.ToLower(config.Method), "-auth") {
		config.Method = config.Method[:len(config.Method)-5]
		config.Auth = true
	}
	return
}

//debug模式
func SetDebug(d DebugLog) {
	Debug = d
}

// 用于命令行覆盖配置文件中指定的选项
func UpdateConfig(old, new *Config) {
	// Using reflection here is not necessary, but it's a good exercise.
	// For more information on reflections in Go, read "The Laws of Reflection"
	// http://golang.org/doc/articles/laws_of_reflection.html
	newVal := reflect.ValueOf(new).Elem()
	oldVal := reflect.ValueOf(old).Elem()

	// typeOfT := newVal.Type()
	for i := 0; i < newVal.NumField(); i++ {
		newField := newVal.Field(i)
		oldField := oldVal.Field(i)
		// log.Printf("%d: %s %s = %v\n", i,
		// typeOfT.Field(i).Name, newField.Type(), newField.Interface())
		switch newField.Kind() { //根据不同的类型，处理不同数据
		case reflect.Interface:
			if fmt.Sprintf("%v", newField.Interface()) != "" {
				oldField.Set(newField)
			}
		case reflect.String:
			s := newField.String()
			if s != "" {
				oldField.SetString(s)
			}
		case reflect.Int:
			i := newField.Int()
			if i != 0 {
				oldField.SetInt(i)
			}
		}
	}

	old.Timeout = new.Timeout
	readTimeout = time.Duration(old.Timeout) * time.Second //读取配置文件中超时时间
}
