package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
)

// Independently pinned root and exact active grant. The witnesses verify both
// signatures. This local check verifies their digest commitment, not the proofs.
func (q *freshQuorum) expectedDualDigest(sequence int64) (string, error) {
	if sequence < 1 || sequence > 9007199254740991 || !strongAddr.MatchString(q.pqAddress) || !strongDevice.MatchString(q.pqDevice) {
		return "", errors.New("invalid dual authority context")
	}
	for _, p := range []string{q.dualRootPin, q.pqKemPin, q.pqDsaPin} {
		if !hashRE.MatchString(p) {
			return "", errors.New("invalid dual authority pin")
		}
	}
	// All strings validated above are ASCII without JSON escapes. Field order
	// matches pq_profile.canonical and active votes must commit to true.
	canonical, err := json.Marshal([]any{"quantic-pq-profile-lab/v1", q.pqAddress, q.pqDevice, q.pqKemPin, q.pqDsaPin, sequence, true})
	if err != nil {
		return "", err
	}
	root, _ := hex.DecodeString(q.dualRootPin)
	grant, _ := hex.DecodeString(hexHash(canonical))
	data := append([]byte("quantic-pq-dual-vote-lab/v1\x00"), root...)
	data = append(data, grant...)
	return hexHash(data), nil
}
