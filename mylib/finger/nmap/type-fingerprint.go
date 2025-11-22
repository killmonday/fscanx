package gonmap

import "github.com/killmonday/fscanx/mylib/finger/common"

type FingerPrint struct {
	ProbeName        string `json:"probe_name,omitempty"`
	MatchRegexString string `json:"match_regex,omitempty"`

	Service         string `json:"service,omitempty"`
	ProductName     string `json:"product_name,omitempty"`
	Version         string `json:"version,omitempty"`
	Info            string `json:"info,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	OperatingSystem string `json:"operating_system,omitempty"`
	DeviceType      string `json:"device_type,omitempty"`

	// CPE信息，支持多个CPE条目
	CPEs []string `json:"cpes,omitempty"`
	// 解析后的CPE属性
	CPEAttributes []*common.Attributes `json:"cpe_attributes,omitempty"`
	//  p/vendorproductname/
	//	v/version/
	//	i/info/
	//	h/hostname/
	//	o/operatingsystem/
	//	d/devicetype/
	//	c/cpe/ - CPE信息
}

// ToFrameworks 将FingerPrint转换为多个common.Framework，支持多个CPE app
func (fp *FingerPrint) ToFrameworks() []*common.Framework {
	if fp.Service == "" {
		return nil
	}

	var frameworks []*common.Framework

	// 修复协议名称
	service := FixProtocol(fp.Service)

	// 如果有CPE app类型的属性，为每个创建一个Framework
	appCPEAttrs := fp.getAppCPEAttributes()

	if len(appCPEAttrs) > 0 {
		// 为每个app类型的CPE创建Framework
		for _, attr := range appCPEAttrs {
			framework := common.NewFramework(service, common.FrameFromNmap)
			fp.populateFramework(framework, attr)
			frameworks = append(frameworks, framework)
		}
	} else {
		// 没有CPE app信息，创建基本的Framework
		framework := common.NewFramework(service, common.FrameFromNmap)
		fp.populateFramework(framework, nil)
		frameworks = append(frameworks, framework)
	}

	return frameworks
}

// getAppCPEAttributes 获取所有app类型的CPE属性
func (fp *FingerPrint) getAppCPEAttributes() []*common.Attributes {
	var appAttrs []*common.Attributes
	for _, attr := range fp.CPEAttributes {
		if attr != nil && attr.Part == "a" { // 只关心application类型
			appAttrs = append(appAttrs, attr)
		}
	}
	return appAttrs
}

// populateFramework 填充Framework的信息
func (fp *FingerPrint) populateFramework(framework *common.Framework, cpeAttr *common.Attributes) {
	// 优先使用CPE属性，其次使用FingerPrint属性
	if cpeAttr != nil {
		// 使用CPE中的产品和版本信息
		if cpeAttr.Product != "" {
			framework.Product = cpeAttr.Product
		}
		if cpeAttr.Version != "" {
			framework.Version = cpeAttr.Version
		}
		// 将厂商信息添加到标签中
		if cpeAttr.Vendor != "" {
			framework.Tags = append(framework.Tags, "vendor:"+cpeAttr.Vendor)
		}
	} else {
		// 使用FingerPrint中的基本信息
		if fp.ProductName != "" {
			framework.Product = fp.ProductName
		}
		if fp.Version != "" {
			framework.Version = fp.Version
		}
	}

	// 添加其他信息到标签
	if fp.Info != "" {
		framework.Tags = append(framework.Tags, fp.Info)
	}
	if fp.Hostname != "" {
		framework.Tags = append(framework.Tags, "hostname:"+fp.Hostname)
	}
	if fp.DeviceType != "" {
		framework.Tags = append(framework.Tags, "device:"+fp.DeviceType)
	}

	// 将所有CPE字符串添加到标签中（只保留app类型的）
	for i, cpe := range fp.CPEs {
		if i < len(fp.CPEAttributes) && fp.CPEAttributes[i] != nil && fp.CPEAttributes[i].Part == "a" {
			framework.Tags = append(framework.Tags, "cpe:"+cpe)
		}
	}

	// 标记为主动扫描结果
	framework.Froms = map[common.From]bool{common.FrameFromACTIVE: true}
}
