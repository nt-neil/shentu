package tools

import (
	"context"

	"github.com/nt-neil/shentu/hostenv"
)

// RecordHost records src (hostfacts -record) into a fixture in dir: what
// the facts read, and what the survey (site_profile) reads of the host
// beyond them, so a replay of it answers the survey as the host did (S5,
// v0.5.8 acceptance: cloud-init's configuration was not recorded, and the
// replay lost sudo:nopasswd:cloud-init). mask makes the masker from the
// facts (their human accounts). TestRecordingCoversSurvey holds every read
// of the survey to the recording.
func RecordHost(ctx context.Context, src hostenv.Source, dir string, mask func(*hostenv.Facts) *hostenv.Masker) (*hostenv.Facts, error) {
	rec := hostenv.NewRecorder(src)
	facts := hostenv.Collect(ctx, rec)
	old := hostSource
	hostSource = func() hostenv.Source { return rec }
	Survey(ctx, &Env{})
	hostSource = old
	return facts, rec.Save(dir, mask(facts))
}
