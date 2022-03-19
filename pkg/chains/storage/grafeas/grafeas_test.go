/*
Copyright 2020 The Tekton Authors
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package grafeas

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tektoncd/chains/pkg/chains/formats"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	attestationpb "github.com/grafeas/grafeas/proto/v1beta1/attestation_go_proto"
	commonpb "github.com/grafeas/grafeas/proto/v1beta1/common_go_proto"
	pb "github.com/grafeas/grafeas/proto/v1beta1/grafeas_go_proto"
	"github.com/tektoncd/chains/pkg/config"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	gstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logtesting "knative.dev/pkg/logging/testing"
)

type args struct {
	tr        *v1beta1.TaskRun
	payload   []byte
	signature string
	opts      config.StorageOpts
}

type testConfig struct {
	name    string
	args    args
	wantErr bool
}

type mockGrafeasV1Beta1Server struct {
	// Embed for forward compatibility.
	// Tests will keep working if more methods are added in the future.
	pb.UnimplementedGrafeasV1Beta1Server

	// Assume there is only one project for storing notes and occurences
	occurences map[string]*pb.Occurrence
	notes      map[string]*pb.Note
}

var grafeasServer mockGrafeasV1Beta1Server

func TestBackend_ServerConnCheck(t *testing.T) {
	tests := []struct {
		serverName string
		wantErr    bool
	}{
		{serverName: "dns:///containeranalysis.googleapis.com", wantErr: false},
		{serverName: "dns:///containeranalysis.fake.com", wantErr: true},
	}

	for _, test := range tests {
		if err := checkTrustedHost(test.serverName); (err != nil) != test.wantErr {
			t.Errorf("The behaviour of checking trusted host is wrong. error = %v, wantErr = %v", err, test.wantErr)
		}
	}
}

func TestBackend_StorePayload(t *testing.T) {
	tests := []testConfig{
		{
			name: "TEST 1: intoto for taskrun, no error",
			args: args{
				tr: &v1beta1.TaskRun{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "foo1",
						Name:      "bar1",
						UID:       types.UID("uid1"),
					},
				},
				payload:   []byte("taskrun payload"),
				signature: "taskrun signature",
				opts:      config.StorageOpts{Key: "taskrun.uuid", PayloadFormat: formats.PayloadTypeInTotoIte6},
			},
			wantErr: false,
		},
		{
			name: "TEST 2: simplesining for oci, no error",
			args: args{
				tr: &v1beta1.TaskRun{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "foo2",
						Name:      "bar2",
						UID:       types.UID("uid2"),
					},
					Status: v1beta1.TaskRunStatus{
						TaskRunStatusFields: v1beta1.TaskRunStatusFields{
							TaskRunResults: []v1beta1.TaskRunResult{
								{Name: "IMAGE_DIGEST", Value: "sha256:cfe4f0bf41c80609214f9b8ec0408b1afb28b3ced343b944aaa05d47caba3e00"},
								{Name: "IMAGE_URL", Value: "gcr.io/test/kaniko-chains1"},
							},
						},
					},
				},
				payload:   []byte("oci payload"),
				signature: "oci signature",
				// the Key field must be the same as the first 12 chars of the image digest
				opts: config.StorageOpts{Key: "cfe4f0bf41c8", PayloadFormat: formats.PayloadTypeSimpleSigning},
			},
			wantErr: false,
		},
		{
			name: "TEST 3: tekton format for taskrun, error",
			args: args{
				tr: &v1beta1.TaskRun{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "foo3",
						Name:      "bar3",
						UID:       types.UID("uid3"),
					},
				},
				opts: config.StorageOpts{Key: "taskrun2.uuid", PayloadFormat: formats.PayloadTypeTekton},
			},
			wantErr: true,
		},
	}

	ctx := context.Background()

	conn, client, err := setupConnection()
	if err != nil {
		t.Fatal("Failed to create grafeas client.")
	}

	defer conn.Close()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := Backend{
				logger: logtesting.TestLogger(t),
				tr:     test.args.tr,
				client: client,
				cfg: config.Config{
					Storage: config.StorageConfigs{
						Grafeas: config.GrafeasConfig{
							ProjectID: "test-project",
							NoteID:    "test-note",
						},
					},
				},
			}
			// test if the attestation of the taskrun/oci artifact can be successfully stored into grafeas server
			// and test if payloads and signatures inside the attestation can be retrieved.
			testInterface(ctx, t, test, backend, test.args.payload, test.args.signature, test.args.opts)
		})
	}

	// test if all occurrences generated from `StorePayload` are what we expect.
	testListOccurrences(ctx, t, client)
}

// test attestation storage and retrieval
func testInterface(ctx context.Context, t *testing.T, test testConfig, backend Backend, payload []byte, signature string, opts config.StorageOpts) {
	if err := backend.StorePayload(ctx, payload, signature, opts); (err != nil) != test.wantErr {
		t.Fatal("Backend.StorePayload() failed. error:", err, "wantErr:", test.wantErr)
	}

	// get uri
	var objectIdentifier string
	switch opts.PayloadFormat {
	case formats.PayloadTypeSimpleSigning:
		objectIdentifier = backend.getOCIURI(opts)
	case formats.PayloadTypeInTotoIte6:
		objectIdentifier = backend.getTaskRunURI()
	default:
		// for other signing formats, grafeas backend will not support
		// we set a fake identifier for testing only
		objectIdentifier = "placeholder_uri"
	}

	// check signature
	expect_signature := map[string][]string{objectIdentifier: []string{signature}}
	got_signature, err := backend.RetrieveSignatures(ctx, opts)
	if err != nil {
		t.Fatal("Backend.RetrieveSignatures() failed. error:", err)
	}

	if !cmp.Equal(got_signature, expect_signature) && !test.wantErr {
		t.Errorf("Wrong signature object received, got=%s", cmp.Diff(got_signature, expect_signature))
	}

	// check payload
	expect_payload := map[string]string{objectIdentifier: string(payload)}
	got_payload, err := backend.RetrievePayloads(ctx, opts)
	if err != nil {
		t.Fatal("RetrievePayloads.RetrievePayloads() failed. error:", err)
	}

	if !cmp.Equal(got_payload, expect_payload) && !test.wantErr {
		t.Errorf("Wrong payload object received, got=%s", cmp.Diff(got_payload, expect_payload))
	}
}

// test occurrences are generated correctly
func testListOccurrences(ctx context.Context, t *testing.T, client pb.GrafeasV1Beta1Client) {
	wanted := &pb.ListOccurrencesResponse{
		Occurrences: []*pb.Occurrence{
			// occurrence for taskrun
			{
				// Occurrence Name will be automatically generated by grafeas server based on resource uri.
				// In this fake grafeas server, we mock this behaviour by just using resource URI as the auto-generated occurrence name.
				// In the real world, the auto-generated name will be in the format of `projects/<PROJECT_NAME>/occurrences/<AUTO-GENERATED-ID>`.
				// i.e. projects/my_project/occurrences/06d6e0d6-ee2b-4629-b44a-2188ac92eee4
				Name:     "/apis/tekton.dev/v1beta1/namespaces/foo1/TaskRun/bar1@uid1",
				Resource: &pb.Resource{Uri: "/apis/tekton.dev/v1beta1/namespaces/foo1/TaskRun/bar1@uid1"},
				NoteName: "projects/test-project/notes/test-note",
				Details: &pb.Occurrence_Attestation{
					Attestation: &attestationpb.Details{
						Attestation: &attestationpb.Attestation{
							Signature: &attestationpb.Attestation_GenericSignedAttestation{
								GenericSignedAttestation: &attestationpb.GenericSignedAttestation{
									// ContentType: for taskrun, this will be GenericSignedAttestation_CONTENT_TYPE_UNSPECIFIED, so this will not show up
									SerializedPayload: []byte("taskrun payload"),
									Signatures: []*commonpb.Signature{
										{
											Signature: []byte("taskrun signature"),
											// PublicKeyId: we're only using KMS for signing which is the one we currently set its reference in attestation
										},
									},
								},
							},
						},
					},
				},
				Envelope: &commonpb.Envelope{
					Payload:     []byte("taskrun payload"),
					PayloadType: "in-toto attestations containing a slsa.dev/provenance predicate",
					Signatures: []*commonpb.EnvelopeSignature{
						{
							Sig: []byte("taskrun signature"),
							// PublicKeyId: we're only using KMS for signing which is the one we currently support for storing its reference in attestation
						},
					},
				},
			},
			// occurrence for OCI image
			{
				Name:     "gcr.io/test/kaniko-chains1@sha256:cfe4f0bf41c80609214f9b8ec0408b1afb28b3ced343b944aaa05d47caba3e00",
				Resource: &pb.Resource{Uri: "gcr.io/test/kaniko-chains1@sha256:cfe4f0bf41c80609214f9b8ec0408b1afb28b3ced343b944aaa05d47caba3e00"},
				NoteName: "projects/test-project/notes/test-note",
				Details: &pb.Occurrence_Attestation{
					Attestation: &attestationpb.Details{
						Attestation: &attestationpb.Attestation{
							Signature: &attestationpb.Attestation_GenericSignedAttestation{
								GenericSignedAttestation: &attestationpb.GenericSignedAttestation{
									ContentType:       attestationpb.GenericSignedAttestation_SIMPLE_SIGNING_JSON,
									SerializedPayload: []byte("oci payload"),
									Signatures: []*commonpb.Signature{
										{
											Signature: []byte("oci signature"),
											// PublicKeyId: we're only using KMS for signing which is the one we currently support for storing its reference in attestation
										},
									},
								},
							},
						},
					},
				},
				Envelope: &commonpb.Envelope{
					Payload:     []byte("oci payload"),
					PayloadType: "in-toto attestations containing a slsa.dev/provenance predicate",
					Signatures: []*commonpb.EnvelopeSignature{
						{
							Sig: []byte("oci signature"),
							// PublicKeyId: we're only using KMS for signing which is the one we currently support for storing its reference in attestation
						},
					},
				},
			},
		},
	}
	got, err := client.ListOccurrences(ctx,
		&pb.ListOccurrencesRequest{
			// This is just a placeholder.
			// ProjectID doesn't matter here because we assume there is only one project in the mocked server.
			Parent: fmt.Sprintf("project/PLACEHOLDER"),
		},
	)
	if err != nil {
		t.Fatal("Failed to create ListOccurrences. error ", err)
	}

	if !cmp.Equal(got, wanted, protocmp.Transform()) {
		t.Errorf("Wrong list of occurrences received, got=%s", cmp.Diff(got, wanted, protocmp.Transform()))
	}
}

// set up the connection between grafeas server and client
// and return the client object to the caller
func setupConnection() (*grpc.ClientConn, pb.GrafeasV1Beta1Client, error) {
	serv := grpc.NewServer()
	pb.RegisterGrafeasV1Beta1Server(serv, &grafeasServer)

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, nil, err
	}

	go serv.Serve(lis)

	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithInsecure())
	if err != nil {
		return nil, nil, err
	}

	client := pb.NewGrafeasV1Beta1Client(conn)
	return conn, client, nil
}

// --------------------- Mocked GrafeasV1Beta1Server interface -----------------
// https://pkg.go.dev/github.com/grafeas/grafeas@v0.2.0/proto/v1beta1/grafeas_go_proto#GrafeasV1Beta1Server
func (s *mockGrafeasV1Beta1Server) CreateOccurrence(ctx context.Context, req *pb.CreateOccurrenceRequest) (*pb.Occurrence, error) {
	if s.occurences == nil {
		s.occurences = make(map[string]*pb.Occurrence)
	}

	occID := req.GetOccurrence().GetResource().GetUri()
	expectedResponse := req.GetOccurrence()
	expectedResponse.Name = occID // mock auto-generated id

	s.occurences[occID] = expectedResponse
	return expectedResponse, nil
}

func (s *mockGrafeasV1Beta1Server) GetOccurrence(ctx context.Context, req *pb.GetOccurrenceRequest) (*pb.Occurrence, error) {
	if s.occurences == nil {
		return nil, gstatus.Error(codes.NotFound, "The occurrence does not exist")
	}
	occID := req.GetName()
	if _, exists := s.occurences[occID]; !exists {
		return nil, gstatus.Error(codes.NotFound, "The occurrence does not exist")
	}
	return s.occurences[occID], nil
}

func (s *mockGrafeasV1Beta1Server) CreateNote(ctx context.Context, req *pb.CreateNoteRequest) (*pb.Note, error) {
	noteID := fmt.Sprintf("%s/notes/%s", req.GetParent(), req.GetNoteId())
	expectedResponse := req.GetNote()
	if s.notes == nil {
		s.notes = make(map[string]*pb.Note)
	}

	if _, exists := s.notes[noteID]; exists {
		return nil, gstatus.Error(codes.AlreadyExists, "note ID already exists")
	}
	s.notes[noteID] = expectedResponse
	return expectedResponse, nil
}

func (s *mockGrafeasV1Beta1Server) ListOccurrences(ctx context.Context, req *pb.ListOccurrencesRequest) (*pb.ListOccurrencesResponse, error) {
	occurrences := []*pb.Occurrence{}

	if req.GetFilter() == "" {
		// if filter is not specified, return all
		for _, occ := range s.occurences {
			occurrences = append(occurrences, occ)
		}
	} else {
		// if filter is specified
		// mock how filter works in ListOccurrencesRequest
		uriFilter := strings.Split(req.GetFilter(), "=")[1] // url filter that has quotes
		uriFilter = uriFilter[1 : len(uriFilter)-1]         // remove quotes

		for id, occ := range s.occurences {
			if id == uriFilter {
				// log.Println("creazy")
				occurrences = append(occurrences, occ)
			}
		}
	}
	return &pb.ListOccurrencesResponse{Occurrences: occurrences}, nil
}
