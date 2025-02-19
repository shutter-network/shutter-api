package watcher

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/identitypreimage"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/service"
	"github.com/shutter-network/shutter-api/common"
	"github.com/shutter-network/shutter-api/internal/data"
)

type Watcher struct {
	db      *pgxpool.Pool
	config  *common.Config
	dbQuery *data.Queries
}

func NewWatcher(config *common.Config, db *pgxpool.Pool) *Watcher {
	return &Watcher{config: config, db: db, dbQuery: data.New(db)}
}

func (w *Watcher) Start(ctx context.Context, runner service.Runner) error {
	decryptionKeysChannel := make(chan *DecryptionKeysEvent)

	p2pMessageWatcher := NewP2PMessageWatcher(w.config, decryptionKeysChannel)
	if err := runner.StartService(p2pMessageWatcher); err != nil {
		return err
	}

	runner.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case event := <-decryptionKeysChannel:
				for _, key := range event.Keys {
					log.Info().Msgf("Received decryption keys identity: %v", key.IdentityPreimage)
					identityPreimage := identitypreimage.IdentityPreimage(key.IdentityPreimage)
					if err := w.dbQuery.InsertDecryptionKey(ctx, data.InsertDecryptionKeyParams{
						Eon:           event.Eon,
						EpochID:       identityPreimage.Bytes(),
						DecryptionKey: key.Key,
					}); err != nil {
						log.Err(err).Msg("failed to insert decryption key")
					}
				}
			}
		}
	})
	return nil
}
