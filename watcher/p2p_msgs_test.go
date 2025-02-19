package watcher

import (
	"context"
	"testing"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/p2pmsg"
	"github.com/shutter-network/shutter-api/common"
	"github.com/stretchr/testify/assert"
)

func TestNewP2PMessageWatcher(t *testing.T) {
	config := &common.Config{}
	channel := make(chan *DecryptionKeysEvent)

	watcher := NewP2PMessageWatcher(config, channel)

	assert.NotNil(t, watcher)
	assert.Equal(t, config, watcher.config)
	assert.Equal(t, channel, watcher.decryptionKeysChannel)
}

func TestMessagePrototypes(t *testing.T) {
	watcher := NewP2PMessageWatcher(nil, nil)
	protos := watcher.MessagePrototypes()

	assert.Len(t, protos, 1)
	_, ok := protos[0].(*p2pmsg.DecryptionKeys)
	assert.True(t, ok)
}

func TestValidateMessage(t *testing.T) {
	watcher := NewP2PMessageWatcher(nil, nil)
	ctx := context.Background()

	tests := []struct {
		name    string
		msg     p2pmsg.Message
		wantErr bool
	}{
		{
			name: "valid message",
			msg: &p2pmsg.DecryptionKeys{
				Eon:  100,
				Keys: []*p2pmsg.Key{{Key: []byte("key1")}},
				Extra: &p2pmsg.DecryptionKeys_Service{
					Service: &p2pmsg.ShutterServiceDecryptionKeysExtra{},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid message type",
			msg: &p2pmsg.DecryptionKeyShares{
				Eon: 100,
				Extra: &p2pmsg.DecryptionKeyShares_Service{
					Service: &p2pmsg.ShutterServiceDecryptionKeySharesExtra{},
				},
			},
			wantErr: true,
		},
		{
			name: "missing keys",
			msg: &p2pmsg.DecryptionKeys{
				Eon:  100,
				Keys: []*p2pmsg.Key{},
				Extra: &p2pmsg.DecryptionKeys_Service{
					Service: &p2pmsg.ShutterServiceDecryptionKeysExtra{},
				},
			},
			wantErr: true,
		},
		{
			name: "no keys",
			msg: &p2pmsg.DecryptionKeys{
				Eon:  100,
				Keys: []*p2pmsg.Key{},
				Extra: &p2pmsg.DecryptionKeys_Service{
					Service: &p2pmsg.ShutterServiceDecryptionKeysExtra{},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := watcher.ValidateMessage(ctx, tt.msg)
			if tt.wantErr {
				assert.Equal(t, result, pubsub.ValidationReject)
			} else {
				assert.Equal(t, result, pubsub.ValidationAccept)
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandleMessage(t *testing.T) {
	channel := make(chan *DecryptionKeysEvent, 1) // buffered channel to prevent blocking
	watcher := NewP2PMessageWatcher(nil, channel)
	ctx := context.Background()

	testMsg := &p2pmsg.DecryptionKeys{
		Eon:        100,
		Keys:       []*p2pmsg.Key{{Key: []byte("key1")}},
		InstanceId: 42,
	}

	responses, err := watcher.HandleMessage(ctx, testMsg)
	assert.NoError(t, err)
	assert.Empty(t, responses)

	// Verify the message was sent to the channel
	select {
	case event := <-channel:
		assert.Equal(t, int64(100), event.Eon)
		assert.Equal(t, testMsg.Keys, event.Keys)
		assert.Equal(t, int64(42), event.InstanceID)
	default:
		t.Error("Expected message on channel but got none")
	}
}
