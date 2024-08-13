package policyhelper

import (
	"context"
	"github.com/golfz/goliath/v2"
	"net/http"
	"testing"
)

// PolicyValidator
type mockPolicyValidator struct {
	Result bool
	Error  error
}

func (mock *mockPolicyValidator) SetResource(resource string)                {}
func (mock *mockPolicyValidator) SetAction(action string)                    {}
func (mock *mockPolicyValidator) AddPropertyString(key string, value string) {}
func (mock *mockPolicyValidator) AddPropertyInteger(key string, value int)   {}
func (mock *mockPolicyValidator) AddPropertyFloat(key string, value float64) {}
func (mock *mockPolicyValidator) AddPropertyBoolean(key string, value bool)  {}
func (mock *mockPolicyValidator) IsAccessAllowed() (bool, error) {
	return false, mock.Error
}
func (mock *mockPolicyValidator) SetError(err error) {
	mock.Error = err
}

func TestAddPolicyToContext(t *testing.T) {
	// Arrange
	wantP := &mockPolicyValidator{
		Result: false,
		Error:  nil,
	}

	// Act
	ctx, err := AddPolicyValidatorToContext(context.Background(), wantP)

	// Assert
	if err != nil {
		t.Error(err)
	}
	if ctx == nil {
		t.Error("Expected context, but got nil")
	}

	gotP := ctx.Value(keyUserPolicy)
	if gotP == nil {
		t.Error("Expected PolicyValidator, but got nil")
	}
	if gotP != wantP {
		t.Errorf("Expected %v, but got %v", wantP, gotP)
	}
}

func TestGetPolicy_Success(t *testing.T) {
	// Arrange
	wantP := &mockPolicyValidator{
		Result: true,
		Error:  nil,
	}
	ctx, _ := AddPolicyValidatorToContext(context.Background(), wantP)
	gCtx := goliath.New()
	r, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	gCtx.SetRequest(r)

	// Act
	gotP := GetPolicy(gCtx)

	// Assert
	if gotP == nil {
		t.Error("Expected PolicyValidator, but got nil")
	}
	if gotP != wantP {
		t.Errorf("Expected %v, but got %v", wantP, gotP)
	}
}

func TestGetPolicy_NotAddPolicyValidator_Fail(t *testing.T) {
	// Arrange
	gCtx := goliath.New()
	r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	gCtx.SetRequest(r)

	// Act
	gotP := GetPolicy(gCtx)
	result, err := gotP.IsAccessAllowed()

	// Assert
	if result != false {
		t.Errorf("Expected false, but got %v", result)
	}
	if err == nil {
		t.Error("Expected error, but got nil")
	}
}
