package netfilter

import (
	"fmt"

	"github.com/Alexmaster12345/netforge-api/internal/models"
	ct "github.com/ti-mo/conntrack"
	"go.uber.org/zap"
)

// ConntrackService reads live flows from the kernel's connection tracking subsystem.
type ConntrackService struct {
	log    *zap.Logger
	dryRun bool
}

func NewConntrackService(log *zap.Logger, dryRun bool) *ConntrackService {
	return &ConntrackService{log: log, dryRun: dryRun}
}

// ListConnections returns all active flows from nf_conntrack.
// Requires CAP_NET_ADMIN. Returns an empty slice in dry-run or on error.
func (s *ConntrackService) ListConnections() ([]*models.Connection, error) {
	if s.dryRun {
		s.log.Info("[dry-run] ListConnections — returning empty list")
		return []*models.Connection{}, nil
	}

	conn, err := ct.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("conntrack dial: %w", err)
	}
	defer conn.Close()

	flows, err := conn.Dump(nil)
	if err != nil {
		return nil, fmt.Errorf("conntrack dump: %w", err)
	}

	out := make([]*models.Connection, 0, len(flows))
	for _, f := range flows {
		c := &models.Connection{
			Protocol:   protoName(f.TupleOrig.Proto.Protocol),
			SourceIP:   f.TupleOrig.IP.SourceAddress.String(),
			SourcePort: f.TupleOrig.Proto.SourcePort,
			DestIP:     f.TupleOrig.IP.DestinationAddress.String(),
			DestPort:   f.TupleOrig.Proto.DestinationPort,
		}
		if f.ProtoInfo.TCP != nil {
			c.State = tcpStateName(f.ProtoInfo.TCP.State)
		}
		c.Packets = f.CountersOrig.Packets
		c.Bytes = f.CountersOrig.Bytes
		out = append(out, c)
	}
	return out, nil
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	default:
		return fmt.Sprintf("proto_%d", p)
	}
}

func tcpStateName(s uint8) string {
	states := []string{
		"NONE", "SYN_SENT", "SYN_RECV", "ESTABLISHED",
		"FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT",
		"CLOSE", "LISTEN",
	}
	if int(s) < len(states) {
		return states[s]
	}
	return fmt.Sprintf("UNKNOWN_%d", s)
}
