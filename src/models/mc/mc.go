package mc

import (
	"encoding/json"
	"fmt"

	"github.com/bradfitz/gomemcache/memcache"
)

type TAuthCache struct {
	TAuthToken       string `json:"tauth_token"`
	TAuthTokenSecret string `json:"tauth_token_secret"`
	ExpireTime       int64  `json:"expire_time"`
}

type McClient struct {
	Client *memcache.Client
}

func Init(host string, port int) *McClient {
	server := fmt.Sprintf("%s:%d", host, port)
	mc := memcache.New(server)
	return &McClient{Client: mc}
}

func (mc *McClient) GetFromCache(cacheKey string) (*TAuthCache, error) {
	item, err := mc.Client.Get(cacheKey)
	if err != nil {
		return nil, err
	}

	var cacheData TAuthCache
	if err := json.Unmarshal(item.Value, &cacheData); err != nil {
		return nil, err
	}
	return &cacheData, nil
}
