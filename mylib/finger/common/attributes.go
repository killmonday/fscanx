package common

import "github.com/facebookincubator/nvdtools/wfn"

func NewAttributesWithAny() *Attributes {
	return &Attributes{}
}

func NewAttributesWithCPE(s string) *Attributes {
	attr, err := wfn.Parse(s)
	if err != nil {
		return nil
	}
	return &Attributes{
		Part:      attr.Part,
		Vendor:    attr.Vendor,
		Product:   attr.Product,
		Version:   attr.Version,
		Update:    attr.Update,
		Edition:   attr.Edition,
		SWEdition: attr.SWEdition,
		TargetSW:  attr.TargetSW,
		TargetHW:  attr.TargetHW,
		Other:     attr.Other,
		Language:  attr.Language,
	}
}

type Attributes struct {
	Part      string `json:"part" yaml:"part"`
	Vendor    string `json:"vendor" yaml:"vendor"`
	Product   string `json:"product" yaml:"product"`
	Version   string `json:"version,omitempty" yaml:"version,omitempty"`
	Update    string `json:"update,omitempty" yaml:"update,omitempty"`
	Edition   string `json:"edition,omitempty" yaml:"edition,omitempty"`
	SWEdition string `json:"sw_edition,omitempty" yaml:"sw_edition,omitempty"`
	TargetSW  string `json:"target_sw,omitempty" yaml:"target_sw,omitempty"`
	TargetHW  string `json:"target_hw,omitempty" yaml:"target_hw,omitempty"`
	Other     string `json:"other,omitempty" yaml:"other,omitempty"`
	Language  string `json:"language,omitempty" yaml:"language,omitempty"`
}

func (a *Attributes) WFN() *wfn.Attributes {
	return &wfn.Attributes{
		Part:      a.Part,
		Vendor:    a.Vendor,
		Product:   a.Product,
		Version:   a.Version,
		Update:    a.Update,
		Edition:   a.Edition,
		SWEdition: a.SWEdition,
		TargetSW:  a.TargetSW,
		TargetHW:  a.TargetHW,
		Other:     a.Other,
	}
}

func (a *Attributes) URI() string {
	return a.WFN().BindToURI()
}

func (a *Attributes) String() string {
	return a.WFN().BindToFmtString()
}

func (a *Attributes) WFNString() string {
	return a.WFN().String()
}
