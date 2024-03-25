package policyhelper

import (
	"context"
	"errors"
	"github.com/golfz/goliath/v2"
	"github.com/golfz/policy"
	"github.com/golfz/policyhelper/kpolicy"
)

func AddPolicyToContext(ctx context.Context, policies []byte, userGetter policy.UserPropertyGetter) (context.Context, error) {
	p, err := policy.ParsePolicyArray(policies)
	if err != nil {
		return nil, err
	}
	ctrl := policy.ValidationController{
		Policies:           p,
		UserPropertyGetter: userGetter,
	}
	ctx = context.WithValue(ctx, kpolicy.UserPolicy, ctrl)
	return ctx, nil
}

func GetPolicy(ctx goliath.Goliath) policy.Validator {
	p, ok := ctx.Request().Context().Value(kpolicy.UserPolicy).(policy.ValidationController)
	if !ok {
		return &policy.ValidationController{
			Err: errors.New("policy not found in context"),
		}
	}
	return &p
}
