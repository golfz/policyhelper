package policyhelper

import (
	"errors"
	"github.com/golfz/goliath/v2"
	"github.com/golfz/policy"
	"github.com/golfz/policyhelper/kpolicy"
)

func GetPolicy(ctx goliath.Goliath) policy.Policy {
	ctxPolicy := ctx.Request().Context().Value(kpolicy.UserPolicy)
	p, ok := ctxPolicy.(policy.Policy)
	if !ok {
		return policy.Policy{
			Version:   0,
			PolicyID:  "",
			Statement: nil,
			Error:     errors.New("cannot do type assertion!"),
		}
	}
	return p
}
