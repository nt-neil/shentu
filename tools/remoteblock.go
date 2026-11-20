package tools

import (
	"context"
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

// RemoteBlockCheck runs the checks block_ip runs from a chat channel, in the
// same order, without blocking: RemoteRefused, Preview (checkBlock), then
// blockGate with env.Remote set (internalAddr, remoteGate). The proposal
// buttons call it when a button is offered and again when it is pressed, and
// the dispatch archive stores its code; block_ip's Run still checks again.
// preview is what Preview showed; err is the gate's message, for the
// server's log only.
// TODO(B): implement.
func RemoteBlockCheck(ctx context.Context, env *Env, ip net.IP) (preview string, code BlockCode, err error) {
	return "", BlockStateError, errors.New("not implemented")
}
