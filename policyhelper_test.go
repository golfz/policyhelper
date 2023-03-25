package policyhelper

import (
	"context"
	"github.com/golfz/goliath/v2"
	"github.com/golfz/policy"
	"github.com/golfz/policyhelper/kpolicy"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestGetPolicy(t *testing.T) {
	ctxWithPolicy := goliath.New()
	r := &http.Request{}
	p1 := policy.Policy{}
	ctx := r.Context()
	ctx = context.WithValue(ctx, kpolicy.UserPolicy, p1)
	r = r.WithContext(ctx)
	ctxWithPolicy.SetRequest(r)

	p2 := GetPolicy(ctxWithPolicy)
	assert.NoError(t, p2.Error)
	assert.Equal(t, p1, p2)
}

func TestGetPolicy_Error(t *testing.T) {
	ctxWithoutPolicy := goliath.New()
	ctxWithoutPolicy.SetRequest(&http.Request{})
	p := GetPolicy(ctxWithoutPolicy)
	assert.Error(t, p.Error)
}
