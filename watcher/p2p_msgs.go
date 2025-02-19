package watcher

import (
	"context"
	"fmt"
	"math"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/service"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/p2p"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/p2pmsg"
	"github.com/shutter-network/shutter-api/common"
)

type P2PMessageWatcher struct {
	config                *common.Config
	decryptionKeysChannel chan *DecryptionKeysEvent
}

type DecryptionKeysEvent struct {
	Eon        int64
	Keys       []*p2pmsg.Key
	InstanceID int64
}

func NewP2PMessageWatcher(config *common.Config, decryptionKeysChannel chan *DecryptionKeysEvent) *P2PMessageWatcher {
	return &P2PMessageWatcher{
		config:                config,
		decryptionKeysChannel: decryptionKeysChannel,
	}
}

func (p *P2PMessageWatcher) Start(ctx context.Context, runner service.Runner) error {
	p2pService, err := p2p.New(p.config.P2P)
	if err != nil {
		return err
	}
	p2pService.AddMessageHandler(p)
	return runner.StartService(p2pService)
}

func (pmw *P2PMessageWatcher) MessagePrototypes() []p2pmsg.Message {
	return []p2pmsg.Message{
		&p2pmsg.DecryptionKeys{},
	}
}

func (pmw *P2PMessageWatcher) ValidateMessage(_ context.Context, msgUntyped p2pmsg.Message) (pubsub.ValidationResult, error) {
	msg, ok := msgUntyped.(*p2pmsg.DecryptionKeys)
	if !ok {
		return pubsub.ValidationReject, nil
	}
	extra := msg.Extra.(*p2pmsg.DecryptionKeys_Service).Service
	if extra == nil {
		return pubsub.ValidationReject, nil
	}
	if msg.Eon > math.MaxInt64 {
		return pubsub.ValidationReject, fmt.Errorf("eon %d overflows int64", msg.Eon)
	}
	if len(msg.Keys) == 0 {
		return pubsub.ValidationReject, fmt.Errorf("no keys in message")
	}

	return pubsub.ValidationAccept, nil
}

func (pmw *P2PMessageWatcher) HandleMessage(ctx context.Context, msg p2pmsg.Message) ([]p2pmsg.Message, error) {
	switch msg := msg.(type) {
	case *p2pmsg.DecryptionKeys:
		pmw.decryptionKeysChannel <- &DecryptionKeysEvent{
			Eon:        int64(msg.Eon),
			Keys:       msg.Keys,
			InstanceID: int64(msg.InstanceId),
		}
	}
	return []p2pmsg.Message{}, nil
}
