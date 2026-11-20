package tools

import (
	"context"
	"encoding/json"
	"errors"
	"net"
)

// BlockCode is why a block from a chat channel would be refused, as a fixed
// word: what the dispatch archive stores and a proposal button shows instead
// of the gate's message (which can quote text an attacker logged).
type BlockCode string

const (
	BlockOK           BlockCode = "ok"            // every check passed at that moment; never a permission by itself
	BlockUnverified   BlockCode = "unverified"    // its attempts are in logs that cannot be believed
	BlockOverflow     BlockCode = "overflow"      // only an overflow or summary group may hold it (MayHold included)
	BlockWeak         BlockCode = "weak"          // L1 or Unknown only
	BlockInternal     BlockCode = "internal"      // internalAddr, loopback, this host's own address
	BlockLockout      BlockCode = "lockout"       // checkBlock: gateway, DNS server, the SSH peer
	BlockNotCanonical BlockCode = "not_canonical" // the proposal's address was not written in canonical form
	BlockNoEvidence   BlockCode = "no_evidence"   // no group lists it and sshd logged no logins from it
	BlockStateError   BlockCode = "state_error"   // the attack state or the logs could not be read
)

// codedError is a refusal with its BlockCode; Error is the message as it
// always was.
type codedError struct {
	code BlockCode
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

func coded(code BlockCode, err error) error { return &codedError{code, err} }

// codeOf is err's BlockCode: BlockOK for nil, BlockStateError for a refusal
// that carries none (fail closed: it is never taken for ok).
func codeOf(err error) BlockCode {
	if err == nil {
		return BlockOK
	}
	if c, ok := RefusalCode(err); ok {
		return c
	}
	return BlockStateError
}

// RefusalCode is the BlockCode a check's refusal carries; false for nil and
// for an error that is not a refusal (an nft failure, say).
func RefusalCode(err error) (BlockCode, bool) {
	var c *codedError
	if errors.As(err, &c) {
		return c.code, true
	}
	return "", false
}

// ProposalReason is the reason a block from a proposal button gives.
const ProposalReason = "proposed by a sub-agent, pressed in Telegram"

// ProposalBlockArgs is block_ip's arguments for a proposal button: the
// address and ProposalReason, never an override. The check and the press
// use the same.
func ProposalBlockArgs(ip net.IP) json.RawMessage {
	b, _ := json.Marshal(ipArgs{IP: ip.String(), Reason: ProposalReason})
	return b
}

// RemoteBlockCheck runs the checks block_ip runs from a chat channel, in the
// same order, without blocking: RemoteRefused, Preview (checkBlock), then
// blockGate with env.Remote set (internalAddr, remoteGate). The proposal
// buttons call it when a button is offered and again when it is pressed, and
// the dispatch archive stores its code; block_ip's Run still checks again.
// preview is what Preview showed; err is the gate's message, for the
// server's log only.
func RemoteBlockCheck(ctx context.Context, env *Env, ip net.IP) (preview string, code BlockCode, err error) {
	if ip == nil {
		return "", BlockNotCanonical, errors.New("not an IP address")
	}
	remote := Env{Remote: true}
	if env != nil {
		remote = *env
		remote.Remote = true
	}
	args := ProposalBlockArgs(ip)
	if err := RemoteRefused(&remote, blockIP.Name, args); err != nil {
		return "", codeOf(err), err
	}
	preview, err = blockIP.Preview(args)
	if err != nil {
		return "", codeOf(err), err
	}
	_, ip4, _, err := checkBlock(args) // the address as Run will block it
	if err != nil {
		return "", codeOf(err), err
	}
	if err := blockGate(ctx, &remote, ip4, false); err != nil {
		return preview, codeOf(err), err
	}
	return preview, BlockOK, nil
}
