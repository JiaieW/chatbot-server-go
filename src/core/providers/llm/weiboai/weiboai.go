package weiboai

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"xiaozhi-server-go/src/core/providers/llm"
	"xiaozhi-server-go/src/core/types"
	"xiaozhi-server-go/src/models/mc"

	"github.com/sashabaranov/go-openai"
)

type Provider struct {
	*llm.BaseProvider

	appKey     string
	baseURL    string
	httpClient *http.Client
	mcClient   *mc.McClient
	uid        string
	mu         sync.Mutex
}

// WeiboAIResponse 微博AI接口响应结构
type WeiboAIResponse struct {
	Code          int             `json:"code"`
	ResponseData  json.RawMessage `json:"response_data"`
	RequestParams json.RawMessage `json:"request_params"`
	Msg           string          `json:"msg"`
	TaskID        string          `json:"task_id"`
	RequestID     string          `json:"request_id"`
}

// TauthResponse Tauth认证响应结构
type TauthResponse struct {
	TauthToken       string `json:"tauth_token"`
	TauthTokenSecret string `json:"tauth_token_secret"`
	ExpireTime       int64  `json:"expire_time"`
}

func init() {
	llm.Register("weiboai", NewProvider)
}

func NewProvider(config *llm.Config) (llm.Provider, error) {
	base := llm.NewBaseProvider(config)
	provider := &Provider{
		BaseProvider: base,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
	}

	// 从配置中提取参数
	if appKey, ok := config.Extra["app_key"].(string); ok {
		provider.appKey = appKey
	}
	// 优先从Extra中读取base_url，如果没有则使用config.BaseURL
	if baseURL, ok := config.Extra["base_url"].(string); ok {
		provider.baseURL = baseURL
	} else if config.BaseURL != "" {
		provider.baseURL = config.BaseURL
	} else {
		provider.baseURL = "http://i.aigc.weibo.com"
	}
	if uid, ok := config.Extra["uid"].(string); ok {
		provider.uid = uid
	} else {
		provider.uid = "123456" // 默认值
	}

	// 初始化memcache客户端
	if mcHost, ok := config.Extra["mc_host"].(string); ok {
		if mcPort, ok := config.Extra["mc_port"].(int); ok {
			provider.mcClient = mc.Init(mcHost, mcPort)
		}
	}

	return provider, nil
}

func (p *Provider) Initialize() error {
	if p.appKey == "" {
		return fmt.Errorf("缺少app_key配置")
	}

	// 测试连接
	_, err := p.getTauthToken()
	if err != nil {
		return fmt.Errorf("Tauth认证失败: %v", err)
	}

	return nil
}

func (p *Provider) Cleanup() error {
	if p.httpClient != nil {
		p.httpClient.CloseIdleConnections()
	}
	return nil
}

func (p *Provider) GetSessionID() string {
	return p.SessionID
}

func (p *Provider) SetIdentityFlag(idType string, flag string) {
	// 可以用于设置用户身份标识
	if idType == "uid" {
		p.uid = flag
	}
}

// getTauthToken 获取Tauth认证token
func (p *Provider) getTauthToken() (*TauthResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 先从memcache获取，使用正确的缓存key格式
	if p.mcClient != nil {
		cacheKey := fmt.Sprintf("weibo.api.tauth.%s", p.appKey)
		if cached, err := p.mcClient.GetFromCache(cacheKey); err == nil && cached != nil {
			// 检查是否过期
			if cached.ExpireTime > time.Now().Unix() && cached.TAuthToken != "" && cached.TAuthTokenSecret != "" {
				return &TauthResponse{
					TauthToken:       cached.TAuthToken,
					TauthTokenSecret: cached.TAuthTokenSecret,
					ExpireTime:       cached.ExpireTime,
				}, nil
			}
		}
	}

	// 从API获取新的token
	tokenURL := fmt.Sprintf("http://i.api.weibo.com/tauth2/access_token.json?source=%s&ips=127.0.0.1&ttl=172800", p.appKey)
	resp, err := p.httpClient.Get(tokenURL)
	if err != nil {
		return nil, fmt.Errorf("获取Tauth token失败: %v", err)
	}
	defer resp.Body.Close()

	var tauthResp TauthResponse
	if err := json.NewDecoder(resp.Body).Decode(&tauthResp); err != nil {
		return nil, fmt.Errorf("解析Tauth响应失败: %v", err)
	}

	if tauthResp.TauthToken == "" || tauthResp.TauthTokenSecret == "" {
		return nil, fmt.Errorf("Tauth token或secret为空")
	}

	return &tauthResp, nil
}

// buildTauthHeader 构建Tauth认证头
func (p *Provider) buildTauthHeader() (string, error) {
	tauthResp, err := p.getTauthToken()
	if err != nil {
		return "", err
	}

	// 构建参数，参考你的代码格式
	values := map[string]string{
		"token": tauthResp.TauthToken,
		"param": fmt.Sprintf("uid=%s", p.uid),
	}

	// 生成签名
	h := hmac.New(sha1.New, []byte(tauthResp.TauthTokenSecret))
	h.Write([]byte(values["param"]))
	signature := h.Sum(nil)
	values["sign"] = base64.StdEncoding.EncodeToString(signature)

	// 构建认证头，参考你的代码格式
	var parts []string
	for k, v := range values {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, k, url.QueryEscape(v)))
	}

	authHeader := "TAuth2 " + strings.Join(parts, ", ")
	return authHeader, nil
}

// convertMessagesToWeiboAI 将消息转换为WeiboAI格式
func (p *Provider) convertMessagesToWeiboAI(messages []types.Message) string {
	if len(messages) == 0 {
		return ""
	}

	// 如果是单条消息，直接返回内容
	if len(messages) == 1 {
		return messages[0].Content
	}

	// 多条消息，拼接上下文
	var parts []string
	for _, msg := range messages {
		if msg.Role == "user" || msg.Role == "assistant" {
			parts = append(parts, msg.Content)
		}
	}
	return strings.Join(parts, "\n")
}

func (p *Provider) Response(ctx context.Context, sessionID string, messages []types.Message) (<-chan string, error) {
	responseChan := make(chan string, 10)

	go func() {
		defer close(responseChan)

		// 构建认证头
		authHeader, err := p.buildTauthHeader()
		if err != nil {
			responseChan <- fmt.Sprintf("【WeiboAI认证失败: %v】", err)
			return
		}

		// 转换消息格式
		message := p.convertMessagesToWeiboAI(messages)

		// 构建请求参数，参考你的代码格式
		params := url.Values{}
		params.Set("message", message)
		params.Set("appkey", p.appKey)

		// 从配置中获取type和model_id
		aiType := "azure" // 默认值
		if typeVal, ok := p.Config().Extra["ai_type"].(string); ok && typeVal != "" {
			aiType = typeVal
		}
		params.Set("type", aiType)

		modelID := ""
		if modelIDVal, ok := p.Config().Extra["model_id"].(string); ok && modelIDVal != "" {
			modelID = modelIDVal
			params.Set("model_id", modelID)
		}

		// 使用use_ext_first参数
		params.Set("use_ext_first", "1")

		// 启用流式输出
		params.Set("stream", "true")
		// 创建请求
		reqURL := fmt.Sprintf("%s/completion?%s", p.baseURL, params.Encode())
		req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(""))
		if err != nil {
			responseChan <- fmt.Sprintf("【创建请求失败: %v】", err)
			return
		}

		// 构建请求体，参考你的代码格式
		var requestBody map[string]interface{}

		// 根据AI类型和模型ID构建不同的请求体
		if aiType == "dashscope" && modelID == "qwen-plus" {
			// qwen-plus 需要特殊处理
			requestBody = map[string]interface{}{
				"model_ext": map[string]interface{}{
					"input": map[string]interface{}{
						"messages": []map[string]interface{}{
							{
								"role":    "user",
								"content": message,
							},
						},
					},
				},
			}
		} else {
			// 其他模型使用标准格式
			requestBody = map[string]interface{}{
				"model_ext": map[string]interface{}{
					"messages": []map[string]interface{}{
						{
							"role":    "user",
							"content": message,
						},
					},
				},
			}
		}

		// 序列化请求体
		bodyBytes, err := json.Marshal(requestBody)
		if err != nil {
			responseChan <- fmt.Sprintf("【序列化请求体失败: %v】", err)
			return
		}

		// 重新创建请求，包含请求体
		req, err = http.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewBuffer(bodyBytes))
		if err != nil {
			responseChan <- fmt.Sprintf("【创建请求失败: %v】", err)
			return
		}

		req.Header.Set("Authorization", authHeader)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Expect", "") // 参考你的代码

		// 发送请求
		resp, err := p.httpClient.Do(req)
		if err != nil {
			responseChan <- fmt.Sprintf("【WeiboAI请求失败: %v】", err)
			return
		}
		defer resp.Body.Close()

		// 检查HTTP状态码
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			responseChan <- fmt.Sprintf("【HTTP错误: %d - %s】", resp.StatusCode, string(body))
			return
		}

		// 流式响应处理
		scanner := bufio.NewScanner(resp.Body)
		var lastText string

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			// 解析每一行的JSON响应
			var weiboResp WeiboAIResponse
			if err := json.Unmarshal([]byte(line), &weiboResp); err != nil {
				continue // 跳过解析失败的行
			}

			// 检查是否有错误响应
			if weiboResp.Code != 200 {
				errorMsg := "服务端网络错误，请联系开发人员排查"
				if weiboResp.Msg != "" {
					errorMsg = fmt.Sprintf("服务端错误: %s，请联系开发人员排查", weiboResp.Msg)
				}
				responseChan <- errorMsg
				return
			}

			// 解析response_data中的内容
			var responseData map[string]interface{}
			if err := json.Unmarshal(weiboResp.ResponseData, &responseData); err != nil {
				continue
			}
			// 提取文本内容 - 适配微博AIGC的响应格式
			if output, ok := responseData["output"].(map[string]interface{}); ok {
				if text, ok := output["text"].(string); ok {
					// 只输出增量部分
					if len(text) > len(lastText) {
						increment := text[len(lastText):]
						responseChan <- increment
						lastText = text
					}
				}
			}
		}
	}()

	return responseChan, nil
}

func (p *Provider) ResponseWithFunctions(ctx context.Context, sessionID string, messages []types.Message, tools []openai.Tool) (<-chan types.Response, error) {
	responseChan := make(chan types.Response, 10)
	go func() {
		defer close(responseChan)

		// 第一次调用 LLM，取最后一条用户消息，附加 tool 提示词
		if len(messages) == 2 && len(tools) > 0 {
			lastMsg := messages[len(messages)-1].Content

			functionBytes, err := json.Marshal(tools)
			if err != nil {
				responseChan <- types.Response{
					Content: fmt.Sprintf("【序列化工具失败: %v】", err),
					Error:   err.Error(),
				}
				return
			}
			functionStr := string(functionBytes)
			modifyMsg := llm.GetSystemPromptForFunction(functionStr) + lastMsg
			messages[len(messages)-1].Content = modifyMsg
		}

		// 如果最后一个是 role="tool"，则附加到 user 消息中
		if len(messages) > 1 && messages[len(messages)-1].Role == "tool" {
			assistantMsg := "\ntool call result: " + messages[len(messages)-1].Content + "\n\n"

			for len(messages) > 1 {
				if messages[len(messages)-1].Role == "user" {
					messages[len(messages)-1].Content = assistantMsg + messages[len(messages)-1].Content
					break
				}
				messages = messages[:len(messages)-1]
			}
		}

		// 调用普通 Response 接口获取结果流
		respChan, err := p.Response(ctx, sessionID, messages)
		if err != nil {
			responseChan <- types.Response{
				Content: fmt.Sprintf("【调用Response失败: %v】", err),
				Error:   err.Error(),
			}
			return
		}

		// 透传结果
		for token := range respChan {
			responseChan <- types.Response{
				Content: token,
			}
		}
	}()

	return responseChan, nil
}
