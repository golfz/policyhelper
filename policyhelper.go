package policyhelper

import (
	"github.com/golfz/goliath/v2"
	"github.com/golfz/policy"
	"github.com/golfz/policyhelper/kpolicy"
)

// (1) this function should return []policy.Policy
// ✅ or (2) return interface that can call IsAccessAllowed(policy.Resource) function
//
// I like the second option (2), because it's more flexible
// and module's controller don't need to know the policy struct
// and don't need to change the code if the policy struct is changed
// and don't need to change the current code

func GetPolicy(ctx goliath.Goliath) policy.Validator {
	ctxPolicy := ctx.Request().Context().Value(kpolicy.UserPolicy)
	p, ok := ctxPolicy.(policy.ValidationController)
	if !ok {
		return &policy.ValidationController{}
	}
	return &p
}
