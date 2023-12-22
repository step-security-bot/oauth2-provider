// Code generated by MockGen. DO NOT EDIT.
// Source: authelia.com/provider/oauth2 (interfaces: AuthorizeResponder)
//
// Generated by this command:
//
//	mockgen -package internal -destination internal/authorize_response.go authelia.com/provider/oauth2 AuthorizeResponder
//

// Package internal is a generated GoMock package.
package internal

import (
	http "net/http"
	url "net/url"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockAuthorizeResponder is a mock of AuthorizeResponder interface.
type MockAuthorizeResponder struct {
	ctrl     *gomock.Controller
	recorder *MockAuthorizeResponderMockRecorder
}

// MockAuthorizeResponderMockRecorder is the mock recorder for MockAuthorizeResponder.
type MockAuthorizeResponderMockRecorder struct {
	mock *MockAuthorizeResponder
}

// NewMockAuthorizeResponder creates a new mock instance.
func NewMockAuthorizeResponder(ctrl *gomock.Controller) *MockAuthorizeResponder {
	mock := &MockAuthorizeResponder{ctrl: ctrl}
	mock.recorder = &MockAuthorizeResponderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthorizeResponder) EXPECT() *MockAuthorizeResponderMockRecorder {
	return m.recorder
}

// AddHeader mocks base method.
func (m *MockAuthorizeResponder) AddHeader(arg0, arg1 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddHeader", arg0, arg1)
}

// AddHeader indicates an expected call of AddHeader.
func (mr *MockAuthorizeResponderMockRecorder) AddHeader(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddHeader", reflect.TypeOf((*MockAuthorizeResponder)(nil).AddHeader), arg0, arg1)
}

// AddParameter mocks base method.
func (m *MockAuthorizeResponder) AddParameter(arg0, arg1 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddParameter", arg0, arg1)
}

// AddParameter indicates an expected call of AddParameter.
func (mr *MockAuthorizeResponderMockRecorder) AddParameter(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddParameter", reflect.TypeOf((*MockAuthorizeResponder)(nil).AddParameter), arg0, arg1)
}

// GetCode mocks base method.
func (m *MockAuthorizeResponder) GetCode() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCode")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetCode indicates an expected call of GetCode.
func (mr *MockAuthorizeResponderMockRecorder) GetCode() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCode", reflect.TypeOf((*MockAuthorizeResponder)(nil).GetCode))
}

// GetHeader mocks base method.
func (m *MockAuthorizeResponder) GetHeader() http.Header {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetHeader")
	ret0, _ := ret[0].(http.Header)
	return ret0
}

// GetHeader indicates an expected call of GetHeader.
func (mr *MockAuthorizeResponderMockRecorder) GetHeader() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetHeader", reflect.TypeOf((*MockAuthorizeResponder)(nil).GetHeader))
}

// GetParameters mocks base method.
func (m *MockAuthorizeResponder) GetParameters() url.Values {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetParameters")
	ret0, _ := ret[0].(url.Values)
	return ret0
}

// GetParameters indicates an expected call of GetParameters.
func (mr *MockAuthorizeResponderMockRecorder) GetParameters() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetParameters", reflect.TypeOf((*MockAuthorizeResponder)(nil).GetParameters))
}
