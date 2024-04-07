// Code generated by MockGen. DO NOT EDIT.
// Source: authelia.com/provider/oauth2 (interfaces: RFC8628DeviceAuthorizeEndpointHandler,RFC8628UserAuthorizeEndpointHandler)
//
// Generated by this command:
//
//	mockgen -package mock -destination testing/mock/device_handler.go authelia.com/provider/oauth2 RFC8628DeviceAuthorizeEndpointHandler,RFC8628UserAuthorizeEndpointHandler
//

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	oauth2 "authelia.com/provider/oauth2"
	gomock "go.uber.org/mock/gomock"
)

// MockRFC8628DeviceAuthorizeEndpointHandler is a mock of RFC8628DeviceAuthorizeEndpointHandler interface.
type MockRFC8628DeviceAuthorizeEndpointHandler struct {
	ctrl     *gomock.Controller
	recorder *MockRFC8628DeviceAuthorizeEndpointHandlerMockRecorder
}

// MockRFC8628DeviceAuthorizeEndpointHandlerMockRecorder is the mock recorder for MockRFC8628DeviceAuthorizeEndpointHandler.
type MockRFC8628DeviceAuthorizeEndpointHandlerMockRecorder struct {
	mock *MockRFC8628DeviceAuthorizeEndpointHandler
}

// NewMockRFC8628DeviceAuthorizeEndpointHandler creates a new mock instance.
func NewMockRFC8628DeviceAuthorizeEndpointHandler(ctrl *gomock.Controller) *MockRFC8628DeviceAuthorizeEndpointHandler {
	mock := &MockRFC8628DeviceAuthorizeEndpointHandler{ctrl: ctrl}
	mock.recorder = &MockRFC8628DeviceAuthorizeEndpointHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRFC8628DeviceAuthorizeEndpointHandler) EXPECT() *MockRFC8628DeviceAuthorizeEndpointHandlerMockRecorder {
	return m.recorder
}

// HandleRFC8628DeviceAuthorizeEndpointRequest mocks base method.
func (m *MockRFC8628DeviceAuthorizeEndpointHandler) HandleRFC8628DeviceAuthorizeEndpointRequest(arg0 context.Context, arg1 oauth2.DeviceAuthorizeRequester, arg2 oauth2.DeviceAuthorizeResponder) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HandleRFC8628DeviceAuthorizeEndpointRequest", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// HandleRFC8628DeviceAuthorizeEndpointRequest indicates an expected call of HandleRFC8628DeviceAuthorizeEndpointRequest.
func (mr *MockRFC8628DeviceAuthorizeEndpointHandlerMockRecorder) HandleRFC8628DeviceAuthorizeEndpointRequest(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandleRFC8628DeviceAuthorizeEndpointRequest", reflect.TypeOf((*MockRFC8628DeviceAuthorizeEndpointHandler)(nil).HandleRFC8628DeviceAuthorizeEndpointRequest), arg0, arg1, arg2)
}

// MockRFC8628UserAuthorizeEndpointHandler is a mock of RFC8628UserAuthorizeEndpointHandler interface.
type MockRFC8628UserAuthorizeEndpointHandler struct {
	ctrl     *gomock.Controller
	recorder *MockRFC8628UserAuthorizeEndpointHandlerMockRecorder
}

// MockRFC8628UserAuthorizeEndpointHandlerMockRecorder is the mock recorder for MockRFC8628UserAuthorizeEndpointHandler.
type MockRFC8628UserAuthorizeEndpointHandlerMockRecorder struct {
	mock *MockRFC8628UserAuthorizeEndpointHandler
}

// NewMockRFC8628UserAuthorizeEndpointHandler creates a new mock instance.
func NewMockRFC8628UserAuthorizeEndpointHandler(ctrl *gomock.Controller) *MockRFC8628UserAuthorizeEndpointHandler {
	mock := &MockRFC8628UserAuthorizeEndpointHandler{ctrl: ctrl}
	mock.recorder = &MockRFC8628UserAuthorizeEndpointHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRFC8628UserAuthorizeEndpointHandler) EXPECT() *MockRFC8628UserAuthorizeEndpointHandlerMockRecorder {
	return m.recorder
}

// HandleRFC8628UserAuthorizeEndpointRequest mocks base method.
func (m *MockRFC8628UserAuthorizeEndpointHandler) HandleRFC8628UserAuthorizeEndpointRequest(arg0 context.Context, arg1 oauth2.DeviceAuthorizeRequester) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HandleRFC8628UserAuthorizeEndpointRequest", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// HandleRFC8628UserAuthorizeEndpointRequest indicates an expected call of HandleRFC8628UserAuthorizeEndpointRequest.
func (mr *MockRFC8628UserAuthorizeEndpointHandlerMockRecorder) HandleRFC8628UserAuthorizeEndpointRequest(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandleRFC8628UserAuthorizeEndpointRequest", reflect.TypeOf((*MockRFC8628UserAuthorizeEndpointHandler)(nil).HandleRFC8628UserAuthorizeEndpointRequest), arg0, arg1)
}

// PopulateRFC8628UserAuthorizeEndpointResponse mocks base method.
func (m *MockRFC8628UserAuthorizeEndpointHandler) PopulateRFC8628UserAuthorizeEndpointResponse(arg0 context.Context, arg1 oauth2.DeviceAuthorizeRequester, arg2 oauth2.DeviceUserAuthorizeResponder) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PopulateRFC8628UserAuthorizeEndpointResponse", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// PopulateRFC8628UserAuthorizeEndpointResponse indicates an expected call of PopulateRFC8628UserAuthorizeEndpointResponse.
func (mr *MockRFC8628UserAuthorizeEndpointHandlerMockRecorder) PopulateRFC8628UserAuthorizeEndpointResponse(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PopulateRFC8628UserAuthorizeEndpointResponse", reflect.TypeOf((*MockRFC8628UserAuthorizeEndpointHandler)(nil).PopulateRFC8628UserAuthorizeEndpointResponse), arg0, arg1, arg2)
}
