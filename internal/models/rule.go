package models

import "time"

// Direction of a firewall rule.
const (
	DirectionIngress = "ingress"
	DirectionEgress  = "egress"
)

// Action applied when a rule matches.
const (
	ActionAccept = "accept"
	ActionDrop   = "drop"
	ActionReject = "reject"
)

// Rule is the core domain object representing a Netfilter rule.
type Rule struct {
	ID              string    `json:"id"`
	Direction       string    `json:"direction"`
	SourceIP        string    `json:"source_ip,omitempty"`
	DestinationPort int       `json:"destination_port,omitempty"`
	Protocol        string    `json:"protocol,omitempty"`
	Action          string    `json:"action"`
	Comment         string    `json:"comment,omitempty"`
	CreatedAt       time.Time `json:"created_at"`

	// Kernel internals — omitted from JSON responses.
	NFTHandle uint64 `json:"-"`
	NFTChain  string `json:"-"`
}

// CreateRuleRequest is the JSON body for POST /api/v1/firewall/rules.
type CreateRuleRequest struct {
	Direction       string `json:"direction"`
	SourceIP        string `json:"source_ip"`
	DestinationPort int    `json:"destination_port"`
	Protocol        string `json:"protocol"`
	Action          string `json:"action"`
	Comment         string `json:"comment"`
}

func (r *CreateRuleRequest) Validate() string {
	switch r.Direction {
	case DirectionIngress, DirectionEgress:
	default:
		return "direction must be 'ingress' or 'egress'"
	}
	switch r.Action {
	case ActionAccept, ActionDrop, ActionReject:
	default:
		return "action must be 'accept', 'drop', or 'reject'"
	}
	if r.Protocol != "" {
		switch r.Protocol {
		case "tcp", "udp", "any":
		default:
			return "protocol must be 'tcp', 'udp', or 'any'"
		}
	}
	if r.DestinationPort < 0 || r.DestinationPort > 65535 {
		return "destination_port must be 0–65535"
	}
	return ""
}
