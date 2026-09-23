// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Package grpc provides the reference gRPC binding for the aic-verifier
// decision core.
//
// It is a real gRPC service (manual ServiceDesc, no protoc) whose payload is
// the JSON decide document (aicverifier.DecideRequestDTO /
// aicverifier.DecideResultDTO): the same decision the HTTP middleware and
// in-process callers reach, served to mTLS/queue peers over the wire.
// Denials travel as an OK gRPC call carrying granted:false — a refusal is a
// decision, not an RPC failure; only transport problems are RPC errors.
//
// The binding lives in a subpackage (not the root) so that consumers who only
// need the HTTP middleware do not build the grpc and protobuf dependency tree.
package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"

	"github.com/varwof/aic-verifier"
)

const (
	// ServiceName is the fully-qualified service name of the reference binding.
	ServiceName = "varwof.aic.v1.AICDecisionService"
	// MethodName is the unary decision method.
	MethodName = "Decide"
	// CodecName is the wire content-subtype.  The payload is the JSON
	// decide document — protobuf is not required for this service.
	CodecName = "aic-json-v1"
)

// jsonCodec is the registered gRPC codec carrying the JSON decide document.
type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error)      { return json.Marshal(v) }
func (jsonCodec) Unmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }
func (jsonCodec) Name() string                       { return CodecName }

func init() { encoding.RegisterCodec(jsonCodec{}) }

// DecisionService serves the Decide unary method over the decision core.
// Build it from the same aicverifier.DecisionServer the HTTP middleware
// shares, so every protocol is one decision.
type DecisionService struct {
	core *aicverifier.DecisionServer
}

// NewDecisionService wraps a decision server for gRPC.
func NewDecisionService(core *aicverifier.DecisionServer) *DecisionService {
	return &DecisionService{core: core}
}

// DecisionServer is the service contract the reference binding serves (why
// the server needs this, forward compatibility for generated stubs).
type DecisionServer interface {
	Decide(context.Context, *aicverifier.DecideRequestDTO) (*aicverifier.DecideResultDTO, error)
	mustEmbedUnimplementedDecisionServer()
}

// UnimplementedDecisionServer must be embedded in implementations not yet
// carrying the mandatory methods, matching grpc-go's generated-code pattern.
type UnimplementedDecisionServer struct{}

func (*UnimplementedDecisionServer) mustEmbedUnimplementedDecisionServer() {}

func (s *DecisionService) mustEmbedUnimplementedDecisionServer() {}

// Decide runs one admission decision from its wire request.  It always
// returns the (possibly denied) decide document; the gRPC error is reserved
// for a request that cannot be decoded.
func (s *DecisionService) Decide(ctx context.Context, req *aicverifier.DecideRequestDTO) (*aicverifier.DecideResultDTO, error) {
	if s == nil || s.core == nil {
		return &aicverifier.DecideResultDTO{Granted: false, Code: aicverifier.ErrConfig.String(), Status: http.StatusInternalServerError, Message: "aic-verifier: decision core not configured"}, nil
	}
	if req == nil {
		return &aicverifier.DecideResultDTO{Granted: false, Code: aicverifier.ErrConfig.String(), Status: http.StatusUnprocessableEntity, Message: "aic-verifier: nil decide request"}, nil
	}
	view, err := req.ToView()
	if err != nil {
		return &aicverifier.DecideResultDTO{Granted: false, Code: aicverifier.ErrConfig.String(), Status: http.StatusUnprocessableEntity, Message: err.Error()}, nil
	}
	ac, err := s.core.Decide(ctx, view)
	out := &aicverifier.DecideResultDTO{}
	if err != nil {
		if ae := aicverifier.AsAuthError(err); ae != nil {
			out.Granted = false
			out.Code = ae.Code.String()
			out.Status = ae.Status
			out.Message = ae.Message
			return out, nil
		}
		out.Granted = false
		out.Code = aicverifier.ErrDenied.String()
		out.Status = http.StatusForbidden
		out.Message = err.Error()
		return out, nil
	}
	out.FromAuthContext(ac)
	return out, nil
}

// grpcDecideHandler adapts the service to a unary method while keeping the
// standard interceptors working (metadata, auth, tracing).
func grpcDecideHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(aicverifier.DecideRequestDTO)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*DecisionService).Decide(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: ServiceName + "/" + MethodName}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(*DecisionService).Decide(ctx, req.(*aicverifier.DecideRequestDTO))
	}
	return interceptor(ctx, in, info, handler)
}

// Register attaches the Decide method to a gRPC registrar (grpc.NewServer etc.).
func (s *DecisionService) Register(gs grpc.ServiceRegistrar) {
	gs.RegisterService(&grpc.ServiceDesc{
		ServiceName: ServiceName,
		HandlerType: (*DecisionServer)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: MethodName, Handler: grpcDecideHandler},
		},
		Metadata: "varwof/aic/decision",
	}, s)
}

// DecisionClient is the reference client for the Decide method.  It drives
// the same wire document as the server, so the decision it returns is read
// directly off the wire rather than re-derived.
type DecisionClient struct {
	cc grpc.ClientConnInterface
}

// NewDecisionClient wraps a grpc connection (or unit-test stub).
func NewDecisionClient(cc grpc.ClientConnInterface) *DecisionClient {
	return &DecisionClient{cc: cc}
}

// Decide performs one admission decision over the wire.  A decision refusal
// returns a non-nil *aicverifier.AuthError (via error); a non-nil *AuthContext
// means granted.  Only transport failures escape as non-AuthError.
func (c *DecisionClient) Decide(ctx context.Context, view *aicverifier.RequestView) (*aicverifier.AuthContext, error) {
	var res aicverifier.DecideResultDTO
	req := view.ToDTO()
	if err := c.cc.Invoke(ctx, ServiceName+"/"+MethodName, req, &res,
		grpc.CallContentSubtype(CodecName)); err != nil {
		return nil, &aicverifier.AuthError{Code: aicverifier.ErrDenied, Status: http.StatusBadGateway, Message: fmt.Sprintf("aic-verifier: grpc decision call failed: %v", err)}
	}
	if !res.Granted {
		code := aicverifier.ErrDenied
		if parsed, err := aicverifier.ParseErrorCode(res.Code); err == nil {
			code = parsed
		}
		status := res.Status
		if status == 0 {
			status = http.StatusForbidden
		}
		return nil, &aicverifier.AuthError{Code: code, Status: status, Message: res.Message}
	}
	ac, err := res.ToAuthContext()
	if err != nil {
		return nil, &aicverifier.AuthError{Code: aicverifier.ErrDenied, Status: http.StatusBadGateway, Message: fmt.Sprintf("aic-verifier: decode grpc decision: %v", err)}
	}
	return ac, nil
}
