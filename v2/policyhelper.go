package policyhelper

import (
	"context"
	"errors"
	"github.com/golfz/policyhelper/v2/kpolicy"
)

type Validator interface {
	SetResource(resource string)
	SetAction(action string)
	AddPropertyString(key string, value string)
	AddPropertyInteger(key string, value int)
	AddPropertyFloat(key string, value float64)
	AddPropertyBoolean(key string, value bool)
	IsAccessAllowed() (bool, error)
}

func AddPolicyToContext(ctx context.Context, policies []byte, userGetter policy.UserPropertyGetter, validationOverrider policy.ValidationOverrider) (context.Context, error) {
	p, err := policy.ParsePolicyArray(policies)
	if err != nil {
		return nil, err
	}
	ctrl := policy.ValidationController{
		Policies:            p,
		UserPropertyGetter:  userGetter,
		ValidationOverrider: validationOverrider,
	}
	ctx = context.WithValue(ctx, kpolicy.UserPolicy, ctrl)
	return ctx, nil
}

func GetPolicy(ctx goliath.Goliath) Validator {
	p, ok := ctx.Request().Context().Value(kpolicy.UserPolicy).(policy.ValidationController)
	if !ok {
		return &policy.ValidationController{
			Err: errors.New("policy not found in context"),
		}
	}
	return &p
}
