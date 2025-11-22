package gonmap

import (
	"fmt"
	"strings"
)

// Service 代表一个服务条目
type Service struct {
	Name        string  `json:"name"`
	Port        int     `json:"port"`
	Protocol    string  `json:"protocol"`
	Probability float64 `json:"probability"`
	Comments    string  `json:"comments,omitempty"`
}

// ServicesData 代表解析后的services数据结构
type ServicesData struct {
	Services []Service `json:"services"`
}

// loadServicesData 加载services数据，为了兼容性保留，但使用全局nmap实例
func loadServicesData() (*ServicesData, error) {
	// 确保nmap已经初始化
	if nmap == nil {
		initNmap()
	}
	
	// 返回nmap实例中的ServicesData
	if nmap.servicesData != nil {
		return nmap.servicesData, nil
	}
	
	return nil, fmt.Errorf("services data not loaded")
}

// GetPortsByServiceName 通过服务名称快速获取端口列表
func GetPortsByServiceName(serviceName string) ([]int, error) {
	data, err := loadServicesData()
	if err != nil {
		return nil, err
	}
	
	serviceName = fixServiceName(serviceName)
	var ports []int
	
	for _, service := range data.Services {
		if fixServiceName(service.Name) == serviceName {
			ports = append(ports, service.Port)
		}
	}
	
	if len(ports) == 0 {
		return nil, fmt.Errorf("service %s not found", serviceName)
	}
	
	return ports, nil
}

// GetNmapServices 返回services数组，保持向后兼容
func GetNmapServices() ([]string, error) {
	// 确保nmap已经初始化
	if nmap == nil {
		initNmap()
	}
	
	if nmap.nmapServices != nil {
		return nmap.nmapServices, nil
	}
	return nil, fmt.Errorf("nmap services not loaded")
}

// GetServicesData 返回完整的services数据结构
func GetServicesData() (*ServicesData, error) {
	return loadServicesData()
}

// GetServiceByPort 根据端口号获取服务名称
func GetServiceByPort(port int) (string, error) {
	// 确保nmap已经初始化
	if nmap == nil {
		initNmap()
	}

	if port >= 0 && port < len(nmap.nmapServices) {
		return nmap.nmapServices[port], nil
	}
	return "unknown", nil
}

// SearchServicesByName 根据服务名称搜索相关服务
func SearchServicesByName(name string) ([]Service, error) {
	data, err := loadServicesData()
	if err != nil {
		return nil, err
	}

	var results []Service
	searchName := strings.ToLower(name)
	
	for _, service := range data.Services {
		if strings.Contains(strings.ToLower(service.Name), searchName) {
			results = append(results, service)
		}
	}
	
	return results, nil
}

// fixServiceName 修复服务名称（本地版本避免重复声明）
func fixServiceName(serviceName string) string {
	// 确保nmap已经初始化
	if nmap == nil {
		initNmap()
	}
	return nmap.fixServiceName(serviceName)
}