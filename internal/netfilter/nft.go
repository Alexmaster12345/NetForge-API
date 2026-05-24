package netfilter

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/Alexmaster12345/netforge-api/internal/models"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// NFTService manages Netfilter rules via nftables netlink.
type NFTService struct {
	log        *zap.Logger
	tableName  string
	dryRun     bool
	conn       *nftables.Conn
	table      *nftables.Table
	inputChain *nftables.Chain
	fwdChain   *nftables.Chain
	outChain   *nftables.Chain
}

// NewNFTService initialises the nftables connection and creates the netforge
// table + chains if they do not already exist. On permission error it falls
// back to dry-run mode so the API remains functional for development.
func NewNFTService(log *zap.Logger, tableName string, dryRun bool) (*NFTService, error) {
	svc := &NFTService{log: log, tableName: tableName, dryRun: dryRun}
	if dryRun {
		log.Warn("NFT service running in dry-run mode — kernel calls skipped")
		return svc, nil
	}

	conn, err := nftables.New()
	if err != nil {
		log.Warn("nftables connection failed — falling back to dry-run", zap.Error(err))
		svc.dryRun = true
		return svc, nil
	}
	svc.conn = conn

	if err := svc.bootstrap(); err != nil {
		log.Warn("nftables bootstrap failed — falling back to dry-run", zap.Error(err))
		svc.dryRun = true
	}
	return svc, nil
}

// bootstrap creates the netforge table and its chains atomically.
func (s *NFTService) bootstrap() error {
	s.table = s.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   s.tableName,
	})

	s.inputChain = s.conn.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    s.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   policyAccept(),
	})
	s.fwdChain = s.conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    s.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   policyAccept(),
	})
	s.outChain = s.conn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    s.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   policyAccept(),
	})

	if err := s.conn.Flush(); err != nil {
		return fmt.Errorf("bootstrap flush: %w", err)
	}
	s.log.Info("nftables bootstrap complete",
		zap.String("table", s.tableName),
		zap.String("family", "ip"))
	return nil
}

// AddRule inserts an nftables rule and returns the kernel handle via rule mutation.
func (s *NFTService) AddRule(rule *models.Rule) error {
	if s.dryRun {
		s.log.Info("[dry-run] AddRule",
			zap.String("id", rule.ID),
			zap.String("action", rule.Action),
			zap.String("source_ip", rule.SourceIP),
			zap.Int("dest_port", rule.DestinationPort))
		return nil
	}

	chain := s.chainFor(rule.Direction)
	exprs, err := s.buildExprs(rule)
	if err != nil {
		return fmt.Errorf("build exprs: %w", err)
	}

	nftRule := &nftables.Rule{
		Table:    s.table,
		Chain:    chain,
		Exprs:    exprs,
		UserData: []byte(rule.ID), // stash our UUID so we can find it back
	}
	s.conn.AddRule(nftRule)
	if err := s.conn.Flush(); err != nil {
		return fmt.Errorf("flush add rule: %w", err)
	}

	// Retrieve the kernel handle that was assigned.
	handle, err := s.findHandle(chain, rule.ID)
	if err != nil {
		s.log.Warn("could not retrieve nft handle — deletion by ID will use UserData scan",
			zap.Error(err))
	}
	rule.NFTHandle = handle
	rule.NFTChain = chain.Name
	return nil
}

// DeleteRule removes a rule from the kernel by its stored handle.
func (s *NFTService) DeleteRule(rule *models.Rule) error {
	if s.dryRun {
		s.log.Info("[dry-run] DeleteRule", zap.String("id", rule.ID))
		return nil
	}

	chain := s.chainFor(rule.Direction)

	// Fast path: delete by handle if known.
	if rule.NFTHandle != 0 {
		if err := s.conn.DelRule(&nftables.Rule{
			Table:  s.table,
			Chain:  chain,
			Handle: rule.NFTHandle,
		}); err != nil {
			return fmt.Errorf("del rule by handle: %w", err)
		}
		return s.conn.Flush()
	}

	// Slow path: scan by UserData UUID.
	rules, err := s.conn.GetRules(s.table, chain)
	if err != nil {
		return fmt.Errorf("get rules: %w", err)
	}
	for _, r := range rules {
		if string(r.UserData) == rule.ID {
			if err := s.conn.DelRule(r); err != nil {
				return fmt.Errorf("del rule: %w", err)
			}
			return s.conn.Flush()
		}
	}
	return fmt.Errorf("rule %s not found in kernel", rule.ID)
}

// FlushTable removes all rules and deletes the netforge table on shutdown.
func (s *NFTService) FlushTable() {
	if s.dryRun || s.conn == nil {
		return
	}
	s.conn.DelTable(s.table)
	if err := s.conn.Flush(); err != nil {
		s.log.Warn("error flushing netforge table on shutdown", zap.Error(err))
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (s *NFTService) chainFor(direction string) *nftables.Chain {
	if direction == models.DirectionEgress {
		return s.outChain
	}
	return s.inputChain
}

func (s *NFTService) findHandle(chain *nftables.Chain, ruleID string) (uint64, error) {
	rules, err := s.conn.GetRules(s.table, chain)
	if err != nil {
		return 0, err
	}
	for _, r := range rules {
		if string(r.UserData) == ruleID {
			return r.Handle, nil
		}
	}
	return 0, fmt.Errorf("rule %s not found after flush", ruleID)
}

// buildExprs composes nftables match expressions from a Rule.
func (s *NFTService) buildExprs(rule *models.Rule) ([]expr.Any, error) {
	var exprs []expr.Any

	// ── Protocol match ────────────────────────────────────────────────────────
	if rule.Protocol != "" && rule.Protocol != "any" {
		var protoNum byte
		switch rule.Protocol {
		case "tcp":
			protoNum = unix.IPPROTO_TCP
		case "udp":
			protoNum = unix.IPPROTO_UDP
		default:
			return nil, fmt.Errorf("unknown protocol: %s", rule.Protocol)
		}
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protoNum}},
		)
	}

	// ── Source IP match ───────────────────────────────────────────────────────
	if rule.SourceIP != "" {
		ip := net.ParseIP(rule.SourceIP)
		if ip == nil {
			return nil, fmt.Errorf("invalid source_ip: %s", rule.SourceIP)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("only IPv4 source IPs are supported: %s", rule.SourceIP)
		}
		exprs = append(exprs,
			// Load src IP from network header (offset 12, 4 bytes) into register 1.
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip4},
		)
	}

	// ── Destination port match ────────────────────────────────────────────────
	if rule.DestinationPort > 0 {
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(rule.DestinationPort))
		exprs = append(exprs,
			// Load dst port from transport header (offset 2, 2 bytes) into register 1.
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: portBytes},
		)
	}

	// ── Verdict ───────────────────────────────────────────────────────────────
	var verdictKind expr.VerdictKind
	switch rule.Action {
	case models.ActionAccept:
		verdictKind = expr.VerdictAccept
	case models.ActionDrop, models.ActionReject:
		// nftables REJECT requires an extra expr; we map it to DROP for simplicity.
		verdictKind = expr.VerdictDrop
	default:
		verdictKind = expr.VerdictDrop
	}
	exprs = append(exprs, &expr.Verdict{Kind: verdictKind})

	return exprs, nil
}

func policyAccept() *nftables.ChainPolicy {
	p := nftables.ChainPolicyAccept
	return &p
}
