// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"google.golang.org/grpc"

	"github.com/varwof/aic-verifier"
)

// stubConn is a ClientConnInterface stand-in: the decision client's mapping
// logic is what is under test, not the transport.  The reply DTO is filled by
// the stub directly (the real wire codec would do that on a live conn).
type stubConn struct {
	err  error
	fill func(reply *aicverifier.DecideResultDTO)
}

func (s *stubConn) Invoke(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	if s.err != nil {
		return s.err
	}
	if s.fill != nil {
		s.fill(reply.(*aicverifier.DecideResultDTO))
	}
	return nil
}

func (s *stubConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("no stream support in stub")
}

func TestDecisionClientTransportError(t *testing.T) {
	c := NewDecisionClient(&stubConn{err: errors.New("conn refused"), fill: nil})
	_, err := c.Decide(context.Background(), &aicverifier.RequestView{})
	if ae := aicverifier.AsAuthError(err); ae == nil || ae.Code != aicverifier.ErrDenied || ae.Status != http.StatusBadGateway {
		t.Fatalf("transport error = %#v, want denied/502", ae)
	}
}

func TestDecisionClientDenialDefaultStatus(t *testing.T) {
	c := NewDecisionClient(&stubConn{fill: func(r *aicverifier.DecideResultDTO) {
		r.Granted = false
		r.Code = "bogus_code" // unparsable → default ErrDenied
		r.Status = 0          // zero → 403
	}})
	_, err := c.Decide(context.Background(), &aicverifier.RequestView{})
	ae := aicverifier.AsAuthError(err)
	if ae == nil || ae.Code != aicverifier.ErrDenied || ae.Status != http.StatusForbidden {
		t.Fatalf("denial = %#v, want denied/403", ae)
	}
}

func TestDecisionClientDenialParsedCode(t *testing.T) {
	c := NewDecisionClient(&stubConn{fill: func(r *aicverifier.DecideResultDTO) {
		r.Granted = false
		r.Code = "chain_invalid"
		r.Status = http.StatusUnauthorized
		r.Message = "bad leaf"
	}})
	_, err := c.Decide(context.Background(), &aicverifier.RequestView{})
	ae := aicverifier.AsAuthError(err)
	if ae == nil || ae.Code != aicverifier.ErrChainInvalid || ae.Status != http.StatusUnauthorized || ae.Message != "bad leaf" {
		t.Fatalf("denial = %#v, want chain_invalid/401", ae)
	}
}

func TestDecisionClientGrantedDecodeError(t *testing.T) {
	c := NewDecisionClient(&stubConn{fill: func(r *aicverifier.DecideResultDTO) {
		r.Granted = true
		r.ClientCertDER = []byte("not a cert") // ToAuthContext must fail
	}})
	_, err := c.Decide(context.Background(), &aicverifier.RequestView{})
	ae := aicverifier.AsAuthError(err)
	if ae == nil || ae.Status != http.StatusBadGateway {
		t.Fatalf("decode error = %#v, want denied/502", ae)
	}
}

func TestDecisionServiceNilRequest(t *testing.T) {
	core := decisionServer(t, testAICCert(t))
	resp, err := NewDecisionService(core).Decide(context.Background(), nil)
	if err != nil {
		t.Fatalf("nil request: %v", err)
	}
	if resp == nil || resp.Granted || resp.Status != http.StatusUnprocessableEntity {
		t.Fatalf("nil request resp = %+v, want granted:false/422", resp)
	}
}

func TestDecisionServiceUnparseableChain(t *testing.T) {
	core := decisionServer(t, testAICCert(t))
	resp, err := NewDecisionService(core).Decide(context.Background(), &aicverifier.DecideRequestDTO{
		CertChainDER: [][]byte{{1, 2, 3}},
	})
	if err != nil {
		t.Fatalf("unparseable chain: %v", err)
	}
	if resp == nil || resp.Granted || resp.Status != http.StatusUnprocessableEntity {
		t.Fatalf("unparseable chain resp = %+v, want granted:false/422", resp)
	}
}

// grpcDecideHandler standalone: decode and interceptor plumbing behave even
// when the decoder rejects the request.
func TestGRPCDecideHandlerDecodeError(t *testing.T) {
	srv := NewDecisionService(&aicverifier.DecisionServer{})
	_, err := grpcDecideHandler(srv, context.Background(),
		func(any) error { return errors.New("decode: malformed") }, nil)
	if err == nil {
		t.Fatal("decoder error must propagate")
	}
}

func TestGRPCDecideHandlerInterceptor(t *testing.T) {
	srv := NewDecisionService(decisionServer(t, testAICCert(t)))
	seenMethod := ""
	interceptor := grpc.UnaryServerInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		seenMethod = info.FullMethod
		out, err := handler(ctx, req)
		return out, err
	})
	// The service will answer granted:false for a nil core; the interceptor
	// still runs and the decision doc is returned.
	resp, err := grpcDecideHandler(srv, context.Background(),
		func(any) error { return nil }, interceptor)
	if err != nil {
		t.Fatalf("grpcDecideHandler interceptor: %v", err)
	}
	if seenMethod != ServiceName+"/"+MethodName {
		t.Fatalf("interceptor saw %q, want %q", seenMethod, ServiceName+"/"+MethodName)
	}
	if r := resp.(*aicverifier.DecideResultDTO); r == nil || r.Granted {
		t.Fatalf("interceptor result = %+v, want granted:false", resp)
	}
}
