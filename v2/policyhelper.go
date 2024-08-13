package policyhelper

import (
	"context"
	"errors"
	"github.com/golfz/goliath/v2"
)

type PolicyValidator interface {
	SetResource(resource string)
	SetAction(action string)
	SetError(err error)
	AddPropertyString(key string, value string)
	AddPropertyInteger(key string, value int)
	AddPropertyFloat(key string, value float64)
	AddPropertyBoolean(key string, value bool)
	IsAccessAllowed() (bool, error)
}

type errPolicyValidator struct {
	err error
}

func (p *errPolicyValidator) SetResource(resource string)                {}
func (p *errPolicyValidator) SetAction(action string)                    {}
func (p *errPolicyValidator) AddPropertyString(key string, value string) {}
func (p *errPolicyValidator) AddPropertyInteger(key string, value int)   {}
func (p *errPolicyValidator) AddPropertyFloat(key string, value float64) {}
func (p *errPolicyValidator) AddPropertyBoolean(key string, value bool)  {}
func (p *errPolicyValidator) IsAccessAllowed() (bool, error) {
	return false, p.err
}
func (p *errPolicyValidator) SetError(err error) {
	p.err = err
}

func AddPolicyValidatorToContext(ctx context.Context, p PolicyValidator) (context.Context, error) {
	ctx = context.WithValue(ctx, keyUserPolicy, p)
	return ctx, nil
}

func GetPolicy(ctx goliath.Goliath) PolicyValidator {
	p, ok := ctx.Request().Context().Value(keyUserPolicy).(PolicyValidator)
	if !ok {
		return &errPolicyValidator{
			err: errors.New("policy not found in context"),
		}
	}
	return p
}
