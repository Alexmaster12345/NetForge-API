package models

// Connection represents an active kernel-tracked network flow from conntrack.
type Connection struct {
	Protocol   string `json:"protocol"`
	SourceIP   string `json:"source_ip"`
	SourcePort uint16 `json:"source_port"`
	DestIP     string `json:"dest_ip"`
	DestPort   uint16 `json:"dest_port"`
	State      string `json:"state,omitempty"` // TCP only
	Packets    uint64 `json:"packets,omitempty"`
	Bytes      uint64 `json:"bytes,omitempty"`
}

// BlacklistEntry is a simplified drop-all rule keyed by source IP.
type BlacklistEntry struct {
	IP      string `json:"ip"`
	Comment string `json:"comment,omitempty"`
	RuleID  string `json:"rule_id"` // underlying Rule ID
}

type AddBlacklistRequest struct {
	IP      string `json:"ip"`
	Comment string `json:"comment"`
}
