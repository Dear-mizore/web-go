package main

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 确保 URL 末尾有 /，并返回处理后的 URL
func ensureTrailingSlash(url string) string {
	if !strings.HasSuffix(url, "/") {
		url += "/"
	}
	return url
}

// 获取目标 URL 的所有 IP 地址
func getIPs(targetURL string) ([]string, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("URL 解析失败: %v", err)
	}
	host := parsedURL.Hostname()

	// 使用 net.LookupIP 函数查询主机名对应的 IP 地址列表
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("无法解析域名 %s: %v", host, err)
	}
	// 将 IP 地址列表转换为字符串切片，便于使用和返回
	ipStrings := make([]string, len(ips))
	for i, ip := range ips {
		ipStrings[i] = ip.String() // 将 net.IP 类型转换为字符串格式
	}
	return ipStrings, nil
}

// 根据状态码返回分类和备注
func categorizeStatus(statusCode int) (string, string) {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return "可访问", "正常访问"
	case statusCode >= 300 && statusCode < 400:
		return "重定向", "重定向"
	case statusCode >= 400 && statusCode < 500:
		return "客户端错误", fmt.Sprintf("%d Client Error", statusCode)
	case statusCode >= 500 && statusCode < 600:
		return "服务器错误", fmt.Sprintf("%d Server Error", statusCode)
	default:
		return "不可访问", fmt.Sprintf("HTTP %d", statusCode)
	}
}

// 保存扫描结果到 Markdown 文件
func saveMarkdown(results []string, fileName string) {
	// 打开文件，如果文件不存在则创建，若文件存在则追加写入
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		// 如果打开文件失败，打印错误信息并返回
		fmt.Printf("保存 Markdown 文件失败: %v\n", err)
		return
	}
	defer file.Close()

	// 文件为空时添加标题,设置文件格式
	fi, err := file.Stat()
	if err != nil || fi.Size() == 0 {
		file.WriteString("# 扫描结果\n\n")
		file.WriteString("| URL | 状态码 | 分类 | 备注 |\n")
		file.WriteString("| --- | ------ | ---- | ---- |\n")
	}

	// 追加扫描结果
	for _, line := range results {
		file.WriteString(line + "\n")
	}
}

// requestWithDelay 发送一个带有随机延迟的HTTP GET请求。
// 参数说明：
// - ctx: 上下文对象，用于控制请求的生命周期。
// - url: 请求的目标URL。
// - minDelay: 延迟的最小值（秒）。
// - maxDelay: 延迟的最大值（秒）。
// - client: 用于发送请求的HTTP客户端。
// - *http.Response: 如果请求成功，返回HTTP响应对象。
// 发起 HTTP 请求并添加延时
func requestWithDelay(ctx context.Context, url string, minDelay, maxDelay int, client *http.Client) (*http.Response, error) {
	if minDelay > 0 && maxDelay > 0 {
		// 在最小和最大延迟之间生成一个随机延迟时间
		delay := time.Duration(rand.Intn(maxDelay-minDelay+1)+minDelay) * time.Second
		// 程序将等待指定的延迟时间
		time.Sleep(delay)
	}
	// 使用上下文和指定的URL创建一个新的HTTP GET请求
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		// 如果创建请求时出错，返回错误信息
		return nil, err
	}

	return client.Do(req)
}

// 清理字典路径中的多余字符
func sanitizeDictPath(path string) string {
	return strings.Trim(path, "/")
}

// 检查路径是否包含常见文件后缀
func hasExtension(path string) bool {
	ext := []string{".php", ".asp", ".jsp", ".html", ".js", ".css", ".py", ".aspx", ".cgi", ".xml", ".json"}
	for _, e := range ext {
		if strings.HasSuffix(path, e) {
			return true
		}
	}
	return false
}

// 去重字典路径

func removeDuplicates(paths []string) []string {
	// 创建一个map来存储唯一的路径。使用struct{}作为值，因为它不占用额外的内存空间。
	uniquePaths := make(map[string]struct{})
	// 创建一个切片来存储去重后的结果。
	var result []string
	// 遍历输入的路径切片。
	for _, path := range paths {
		if _, exists := uniquePaths[path]; !exists {
			// 如果不存在，则将其添加到map和结果切片中。
			uniquePaths[path] = struct{}{}
			result = append(result, path)
		}
		// 如果存在，则跳过该路径，确保结果中不会有重复项。
	}
	// 返回去重后的路径切片。
	return result
}

// 辅助函数: 检查切片中是否包含指定的值
func contains(slice []int, item int) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

// 执行请求的核心函数
// scanURL函数是一个用于扫描URL的函数，接受多个参数，包括目标URL、单词列表路径、结果选择、保存路径、后缀选择、模式选择、最小延迟、最大延迟、线程数、是否保存结果以及一个客户端池。
func scanURL(ctx context.Context, targetURL string, wordlistPaths []string, resultChoice []int, savePath string, addSuffixChoice int, suffixes []string, modeChoice int, minDelay, maxDelay, threadCount int, saveResults bool, clientPool *sync.Pool) {
	ips, err := getIPs(targetURL)
	if err != nil {
		fmt.Printf("获取目标 IP 地址失败: %v\n", err)
		return
	}

	// 针对每个 IP 生成报告
	for _, ip := range ips {
		// 生成不同状态码的报告文件路径
		fileAccessible := filepath.Join(savePath, fmt.Sprintf("report_%s_2xx.md", ip))
		fileRedirect := filepath.Join(savePath, fmt.Sprintf("report_%s_3xx.md", ip))
		fileClientError := filepath.Join(savePath, fmt.Sprintf("report_%s_4xx.md", ip))
		fileServerError := filepath.Join(savePath, fmt.Sprintf("report_%s_5xx.md", ip))

		// 遍历字典文件
		for _, wordlistPath := range wordlistPaths {
			file, err := os.Open(wordlistPath)
			if err != nil {
				fmt.Println("无法打开字典文件:", err)
				return
			}
			defer file.Close()

			// 将字典路径读取到一个切片中
			var paths []string
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				dir := scanner.Text()
				if strings.TrimSpace(dir) != "" {
					paths = append(paths, dir)
				}
			}

			// 去重字典路径
			paths = removeDuplicates(paths)

			// 保存扫描结果的变量
			accessibleResults := make([]string, 0)
			redirectResults := make([]string, 0)
			clientErrorResults := make([]string, 0)
			serverErrorResults := make([]string, 0)

			var mu sync.Mutex
			var wg sync.WaitGroup
			var threadLimiter chan struct{}
			var completedRequests int32
			var startTime = time.Now()

			// 初始化并发控制
			if modeChoice == 1 {
				threadLimiter = make(chan struct{}, threadCount)
			}

			// 对去重后的字典路径进行扫描请求
			for _, dir := range paths {
				// 处理字典项后缀
				if addSuffixChoice == 0 && len(suffixes) > 0 {
					for _, suffix := range suffixes {
						fullURL := targetURL + sanitizeDictPath(dir) + suffix
						processRequest(ctx, fullURL, &wg, threadLimiter, minDelay, maxDelay, &mu, &completedRequests, startTime, resultChoice, accessibleResults, redirectResults, clientErrorResults, serverErrorResults, fileAccessible, fileRedirect, fileClientError, fileServerError, saveResults, clientPool)
					}
				} else {
					fullURL := targetURL + sanitizeDictPath(dir)
					processRequest(ctx, fullURL, &wg, threadLimiter, minDelay, maxDelay, &mu, &completedRequests, startTime, resultChoice, accessibleResults, redirectResults, clientErrorResults, serverErrorResults, fileAccessible, fileRedirect, fileClientError, fileServerError, saveResults, clientPool)
				}
			}

			// 等待所有并发请求完成
			wg.Wait()
		}
	}
}

// 处理请求的具体逻辑
func processRequest(ctx context.Context, url string, wg *sync.WaitGroup, threadLimiter chan struct{}, minDelay, maxDelay int, mu *sync.Mutex, completedRequests *int32, startTime time.Time, resultChoice []int, accessibleResults, redirectResults, clientErrorResults, serverErrorResults []string, fileAccessible, fileRedirect, fileClientError, fileServerError string, saveResults bool, clientPool *sync.Pool) {
	if threadLimiter != nil {
		threadLimiter <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() {
				wg.Done()
				<-threadLimiter
			}()

			client := clientPool.Get().(*http.Client)
			defer clientPool.Put(client)
			// 同步请求
			resp, err := requestWithDelay(ctx, url, minDelay, maxDelay, client)
			statusCode := 0
			statusCategory := "不可访问"
			note := "请求失败"
			if err != nil {
				//请求失败时输出url
				//fmt.Printf("[请求失败] %s\n", url)
			} else {
				defer resp.Body.Close()
				statusCode = resp.StatusCode
				statusCategory, note = categorizeStatus(statusCode)

				// 仅在状态码为 200 时输出到终端
				if statusCode == 200 {
					fmt.Printf("[发现] %s (状态码: %d)\n", url, statusCode)
				}
			}

			result := fmt.Sprintf("| %s | %d | %s | %s |", url, statusCode, statusCategory, note)
			mu.Lock()
			if statusCategory == "可访问" {
				accessibleResults = append(accessibleResults, result)
			} else if statusCategory == "重定向" {
				redirectResults = append(redirectResults, result)
			} else if statusCategory == "客户端错误" {
				clientErrorResults = append(clientErrorResults, result)
			} else if statusCategory == "服务器错误" {
				serverErrorResults = append(serverErrorResults, result)
			}
			mu.Unlock()

			// 增加已完成请求数
			atomic.AddInt32(completedRequests, 1)

			// 输出实时进度
			elapsed := time.Since(startTime)
			progress := atomic.LoadInt32(completedRequests)
			speed := float64(progress) / elapsed.Seconds() // 请求速度（请求/秒）
			fmt.Printf("\r已完成请求: %d, 当前速度: %.2f 请求/秒", progress, speed)

			// 如果选择保存结果，则定期保存
			if saveResults {
				if contains(resultChoice, 0) {
					saveMarkdown(accessibleResults, fileAccessible)
				}
				if contains(resultChoice, 1) {
					saveMarkdown(redirectResults, fileRedirect)
				}
				if contains(resultChoice, 2) {
					saveMarkdown(clientErrorResults, fileClientError)
				}
				if contains(resultChoice, 3) {
					saveMarkdown(serverErrorResults, fileServerError)
				}
			}
		}()
	} else {
		// 同步请求
		client := clientPool.Get().(*http.Client)
		defer clientPool.Put(client)

		resp, err := requestWithDelay(ctx, url, minDelay, maxDelay, client)
		statusCode := 0
		statusCategory := "不可访问"
		note := "请求失败"
		if err != nil {
			//fmt.Printf("[请求失败] %s\n", url)
		} else {
			defer resp.Body.Close()
			statusCode = resp.StatusCode
			statusCategory, note = categorizeStatus(statusCode)

			// 仅在状态码为 200 时输出到终端
			if statusCode == 200 {
				fmt.Printf("[发现] %s (状态码: %d)\n", url, statusCode)
			}
		}

		result := fmt.Sprintf("| %s | %d | %s | %s |", url, statusCode, statusCategory, note)
		mu.Lock()
		if statusCategory == "可访问" {
			accessibleResults = append(accessibleResults, result)
		} else if statusCategory == "重定向" {
			redirectResults = append(redirectResults, result)
		} else if statusCategory == "客户端错误" {
			clientErrorResults = append(clientErrorResults, result)
		} else if statusCategory == "服务器错误" {
			serverErrorResults = append(serverErrorResults, result)
		}
		mu.Unlock()

		// 增加已完成请求数
		atomic.AddInt32(completedRequests, 1)

		// 输出实时进度
		elapsed := time.Since(startTime)
		progress := atomic.LoadInt32(completedRequests)
		speed := float64(progress) / elapsed.Seconds() // 请求速度（请求/秒）
		fmt.Printf("\r已完成请求: %d, 当前速度: %.2f 请求/秒", progress, speed)

		// 如果选择保存结果，则定期保存
		if saveResults {
			if contains(resultChoice, 0) {
				saveMarkdown(accessibleResults, fileAccessible)
			}
			if contains(resultChoice, 1) {
				saveMarkdown(redirectResults, fileRedirect)
			}
			if contains(resultChoice, 2) {
				saveMarkdown(clientErrorResults, fileClientError)
			}
			if contains(resultChoice, 3) {
				saveMarkdown(serverErrorResults, fileServerError)
			}
		}
	}
}

func main() {
	// 创建 http.Client 的 sync.Pool
	clientPool := &sync.Pool{
		New: func() interface{} {
			return &http.Client{
				Timeout: 10 * time.Second,
			}
		},
	}

	// 提示和输入部分
	fmt.Println("=================================================================")
	fmt.Println("此程序仅用于学习和研究目的，请务必遵守当地的相关法律法规。")
	fmt.Println("使用此程序时，您需要确保您拥有目标网站的授权进行扫描。")
	fmt.Println("=================================================================")

	// 获取目标 URL 输入
	fmt.Println("请输入目标 URL (多个 URL 用逗号分隔):")
	var targetURLsInput string
	fmt.Scanln(&targetURLsInput)
	targetURLs := strings.Split(targetURLsInput, ",")
	for i := range targetURLs {
		targetURLs[i] = ensureTrailingSlash(strings.TrimSpace(targetURLs[i]))
	}

	// 获取字典文件路径
	fmt.Println("请输入字典文件路径 (多个文件用逗号分隔):")
	var wordlistPathsInput string
	fmt.Scanln(&wordlistPathsInput)
	wordlistPaths := strings.Split(wordlistPathsInput, ",")
	for i := range wordlistPaths {
		wordlistPaths[i] = strings.TrimSpace(wordlistPaths[i])
	}

	// 获取报告保存路径
	fmt.Println("请输入报告保存路径 (如 D:/scan_results 或 C:/Users/xxx/Documents):")
	var savePath string
	fmt.Scanln(&savePath)
	if savePath == "" {
		savePath = "."
	}

	// 获取请求延迟和并发模式
	fmt.Println("请选择扫描模式:")
	fmt.Println("输入 0 启用延迟请求，输入 1 启用并发线程数:")
	var modeChoice int
	fmt.Scanln(&modeChoice)

	var minDelay, maxDelay, threadCount int
	if modeChoice == 0 {
		fmt.Println("请输入最小延迟时间（秒）:")
		fmt.Scanln(&minDelay)
		fmt.Println("请输入最大延迟时间（秒）:")
		fmt.Scanln(&maxDelay)
	} else {
		fmt.Println("请输入并发线程数:")
		fmt.Scanln(&threadCount)
	}

	// 获取后缀选择
	fmt.Println("是否为字典项添加常见后缀？输入 0 启用，输入 1 不启用:")
	var addSuffixChoice int
	fmt.Scanln(&addSuffixChoice)

	var suffixes []string
	if addSuffixChoice == 0 {
		fmt.Println("请输入后缀（用逗号分隔，如 .asp,.php,.py,.js等）：")
		var suffixesInput string
		fmt.Scanln(&suffixesInput)
		suffixes = strings.Split(suffixesInput, ",")
	}

	// 获取保存结果类型
	fmt.Println("请选择要保存的结果类型: (可以选择多个，用逗号分隔):")
	fmt.Println("输入 0 保存 '可访问' 结果，输入 1 保存 '重定向' 结果，输入 2 保存 '客户端错误' 结果，输入 3 保存 '服务器错误' 结果，输入 4 不保存结果：")
	var resultChoiceInput string
	fmt.Scanln(&resultChoiceInput)
	resultChoiceStrings := strings.Split(resultChoiceInput, ",")
	var resultChoice []int
	for _, v := range resultChoiceStrings {
		var choice int
		fmt.Sscan(v, &choice)
		resultChoice = append(resultChoice, choice)
	}

	// 是否保存结果
	saveResults := resultChoice != nil && resultChoice[0] != 4

	// 创建 context 和取消信号
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 执行扫描任务
	for _, targetURL := range targetURLs {
		scanURL(ctx, targetURL, wordlistPaths, resultChoice, savePath, addSuffixChoice, suffixes, modeChoice, minDelay, maxDelay, threadCount, saveResults, clientPool)
	}
	// 完成后提示并退出
	fmt.Println("\n扫描完成，程序退出。")
}
