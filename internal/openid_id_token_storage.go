// Code generated by MockGen. DO NOT EDIT.
// Source: authelia.com/provider/oauth2/handler/openid (interfaces: OpenIDConnectRequestStorage)
//
// Generated by this command:
//
//	mockgen -package internal -destination internal/openid_id_token_storage.go authelia.com/provider/oauth2/handler/openid OpenIDConnectRequestStorage
//
// Package internal is a generated GoMock package.
package internal

import (
	context "context"
	reflect "reflect"

	oauth2 "authelia.com/provider/oauth2"
	gomock "go.uber.org/mock/gomock"
)

// MockOpenIDConnectRequestStorage is a mock of OpenIDConnectRequestStorage interface.
type MockOpenIDConnectRequestStorage struct {
	ctrl     *gomock.Controller
	recorder *MockOpenIDConnectRequestStorageMockRecorder
}

// MockOpenIDConnectRequestStorageMockRecorder is the mock recorder for MockOpenIDConnectRequestStorage.
type MockOpenIDConnectRequestStorageMockRecorder struct {
	mock *MockOpenIDConnectRequestStorage
}

// NewMockOpenIDConnectRequestStorage creates a new mock instance.
func NewMockOpenIDConnectRequestStorage(ctrl *gomock.Controller) *MockOpenIDConnectRequestStorage {
	mock := &MockOpenIDConnectRequestStorage{ctrl: ctrl}
	mock.recorder = &MockOpenIDConnectRequestStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockOpenIDConnectRequestStorage) EXPECT() *MockOpenIDConnectRequestStorageMockRecorder {
	return m.recorder
}

// CreateOpenIDConnectSession mocks base method.
func (m *MockOpenIDConnectRequestStorage) CreateOpenIDConnectSession(arg0 context.Context, arg1 string, arg2 oauth2.Requester) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateOpenIDConnectSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateOpenIDConnectSession indicates an expected call of CreateOpenIDConnectSession.
func (mr *MockOpenIDConnectRequestStorageMockRecorder) CreateOpenIDConnectSession(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateOpenIDConnectSession", reflect.TypeOf((*MockOpenIDConnectRequestStorage)(nil).CreateOpenIDConnectSession), arg0, arg1, arg2)
}

// DeleteOpenIDConnectSession mocks base method.
func (m *MockOpenIDConnectRequestStorage) DeleteOpenIDConnectSession(arg0 context.Context, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteOpenIDConnectSession", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteOpenIDConnectSession indicates an expected call of DeleteOpenIDConnectSession.
func (mr *MockOpenIDConnectRequestStorageMockRecorder) DeleteOpenIDConnectSession(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteOpenIDConnectSession", reflect.TypeOf((*MockOpenIDConnectRequestStorage)(nil).DeleteOpenIDConnectSession), arg0, arg1)
}

// GetOpenIDConnectSession mocks base method.
func (m *MockOpenIDConnectRequestStorage) GetOpenIDConnectSession(arg0 context.Context, arg1 string, arg2 oauth2.Requester) (oauth2.Requester, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOpenIDConnectSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(oauth2.Requester)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetOpenIDConnectSession indicates an expected call of GetOpenIDConnectSession.
func (mr *MockOpenIDConnectRequestStorageMockRecorder) GetOpenIDConnectSession(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOpenIDConnectSession", reflect.TypeOf((*MockOpenIDConnectRequestStorage)(nil).GetOpenIDConnectSession), arg0, arg1, arg2)
}
