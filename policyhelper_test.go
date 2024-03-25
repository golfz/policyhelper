package policyhelper

import (
	"context"
	"github.com/golfz/goliath/v2"
	"github.com/golfz/policy"
	"github.com/golfz/policyhelper/kpolicy"
	"net/http"
	"os"
	"reflect"
	"testing"
)

type DummyUserGetter struct{}

func (d DummyUserGetter) GetUserProperty(key string) string {
	return ""
}

func TestAddPolicyToContext(t *testing.T) {
	// Arrange
	ctx := context.Background()
	var err error
	b, err := os.ReadFile("test_data/policy_array_full.json")
	if err != nil {
		t.Error(err)
		return
	}
	userGetter := DummyUserGetter{}

	// Act
	ctx, err = AddPolicyToContext(ctx, b, userGetter)
	p := ctx.Value(kpolicy.UserPolicyKey)

	// Assert
	if err != nil {
		t.Error(err)
	}
	if ctx == nil {
		t.Error("Expected context, but got nil")
	}
	if reflect.TypeOf(p) != reflect.TypeOf(policy.ValidationController{}) {
		t.Errorf("Expected policy.ValidationController, but got %v", reflect.TypeOf(p))
	}
}

func TestGetPolicy(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		resource policy.Resource
		expected policy.ResultEffect
	}{
		{
			name: "[partial conditions] matched Deny statement, expect DENIED",
			file: "test_data/1policy_partial_conditions.json",
			resource: policy.Resource{
				Resource: "res:::resource_2",
				Action:   "act:::resource_2:action_1",
				Properties: policy.Property{
					Float: map[string]float64{
						"prop:::resource_2:prop_3": 1.1,
					},
					Boolean: map[string]bool{
						"prop:::resource_2:prop_4": false,
					},
				},
			},
			expected: policy.DENIED,
		},
		{
			name: "[partial conditions] matched Allow statement, expect ALLOWED",
			file: "test_data/1policy_partial_conditions.json",
			resource: policy.Resource{
				Resource: "res:::resource_1",
				Action:   "act:::resource_1:action_1",
				Properties: policy.Property{
					String: map[string]string{
						"prop:::resource_1:prop_1": "hello",
					},
				},
			},
			expected: policy.ALLOWED,
		},
	}

	for _, tt := range tests {
		// Arrange
		ctx := context.Background()
		b, _ := os.ReadFile(tt.file)
		userGetter := DummyUserGetter{}
		ctx, _ = AddPolicyToContext(ctx, b, userGetter)
		gtx := goliath.New()
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
		gtx.SetRequest(r)

		// Act
		p := GetPolicy(gtx)
		result, err := p.IsAccessAllowed(tt.resource)

		// Assert
		if err != nil {
			t.Error(err)
		}
		if result != tt.expected {
			t.Errorf("Expected %v, but got %v", tt.expected, result)
		}
	}
}
