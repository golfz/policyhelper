package policyhelper

import (
	"context"
	"github.com/golfz/goliath/v2"
	"github.com/golfz/policy/v2"
	"github.com/golfz/policyhelper/v2/kpolicy"
	"net/http"
	"os"
	"reflect"
	"testing"
)

type DummyUserGetter struct{}

func (d DummyUserGetter) GetUserProperty(key string) string {
	return ""
}

type MockValidationOverrider struct {
	Result    bool
	Error     error
	WasCalled bool
}

func (mock *MockValidationOverrider) OverridePolicyValidation(policies []policy.Policy, UserPropertyGetter policy.UserPropertyGetter, res policy.Resource) (bool, error) {
	mock.WasCalled = true
	return mock.Result, mock.Error
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
	ctx, err = AddPolicyToContext(ctx, b, userGetter, nil)
	p := ctx.Value(kpolicy.UserPolicy)

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

func TestAddPolicyToContext_UseValidatorOverrideWithoutAnyData(t *testing.T) {
	t.Run("nil policies", func(t *testing.T) {
		// Arrange
		ctx := context.Background()

		// Act
		ctx, errAdd := AddPolicyToContext(ctx, nil, nil, &MockValidationOverrider{
			Result: policy.ALLOWED,
			Error:  nil,
		})
		gtx := goliath.New()
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
		gtx.SetRequest(r)
		validator := GetPolicy(gtx)
		result, errValidate := validator.IsAccessAllowed()

		// Assert
		if errAdd != nil {
			t.Error("Expected nil, but got", errAdd)
		}
		if errValidate != nil {
			t.Error("Expected nil, but got", errValidate)
		}
		if result != policy.ALLOWED {
			t.Errorf("Expected ALLOWED, but got %v", result)
		}
	})

	t.Run("empty slice bytes policies", func(t *testing.T) {
		// Arrange
		ctx := context.Background()

		// Act
		ctx, errAdd := AddPolicyToContext(ctx, []byte{}, nil, &MockValidationOverrider{
			Result: policy.ALLOWED,
			Error:  nil,
		})
		gtx := goliath.New()
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
		gtx.SetRequest(r)
		validator := GetPolicy(gtx)
		result, errValidate := validator.IsAccessAllowed()

		// Assert
		if errAdd != nil {
			t.Error("Expected nil, but got", errAdd)
		}
		if errValidate != nil {
			t.Error("Expected nil, but got", errValidate)
		}
		if result != policy.ALLOWED {
			t.Errorf("Expected ALLOWED, but got %v", result)
		}
	})

}

func TestGetPolicy(t *testing.T) {
	tests := []struct {
		name                    string
		file                    string
		resource                policy.Resource
		mockValidationOverrider policy.ValidationOverrider
		expected                bool
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
			mockValidationOverrider: nil,
			expected:                policy.DENIED,
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
			mockValidationOverrider: nil,
			expected:                policy.ALLOWED,
		},
		{
			name: "Override ALLOWED case to be DENIED case, expect DENIED",
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
			mockValidationOverrider: &MockValidationOverrider{
				Result: policy.DENIED,
				Error:  nil,
			},
			expected: policy.DENIED,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			ctx := context.Background()
			b, _ := os.ReadFile(tt.file)
			userGetter := DummyUserGetter{}
			ctx, _ = AddPolicyToContext(ctx, b, userGetter, tt.mockValidationOverrider)
			gtx := goliath.New()
			r, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
			gtx.SetRequest(r)

			p := GetPolicy(gtx)
			p.SetResource(tt.resource.Resource)
			p.SetAction(tt.resource.Action)
			for k, v := range tt.resource.Properties.String {
				p.AddPropertyString(k, v)
			}
			for k, v := range tt.resource.Properties.Integer {
				p.AddPropertyInteger(k, v)
			}
			for k, v := range tt.resource.Properties.Float {
				p.AddPropertyFloat(k, v)
			}
			for k, v := range tt.resource.Properties.Boolean {
				p.AddPropertyBoolean(k, v)
			}

			// Act
			result, err := p.IsAccessAllowed()

			// Assert
			if err != nil {
				t.Error(err)
			}
			if result != tt.expected {
				t.Errorf("Expected %v, but got %v", tt.expected, result)
			}
		})
	}
}
