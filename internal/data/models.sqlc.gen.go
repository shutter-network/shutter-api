// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.22.0

package data

import ()

type DecryptionKey struct {
	Eon           int64
	EpochID       []byte
	DecryptionKey []byte
}
