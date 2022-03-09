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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tektoncd/chains/pkg/chains/formats"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	attestationpb "github.com/grafeas/grafeas/proto/v1beta1/attestation_go_proto"
	commonpb "github.com/grafeas/grafeas/proto/v1beta1/common_go_proto"
	pb "github.com/grafeas/grafeas/proto/v1beta1/grafeas_go_proto"
	"github.com/tektoncd/chains/pkg/config"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	gstatus "google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logtesting "knative.dev/pkg/logging/testing"
)

type args struct {
	tr           *v1beta1.TaskRun
	trPayload    []byte
	trSignature  string
	trOpts       config.StorageOpts
	ociPayload   []byte
	ociSignature string
	ociOpts      config.StorageOpts
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

func TestBackend_StorePayload(t *testing.T) {
	tests := []testConfig{
		// test 1
		{
			name: "no error, simplesining and intoto",
			args: args{
				tr: &v1beta1.TaskRun{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "foo1",
						Name:      "bar1",
						UID:       types.UID("uid1"),
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
				trPayload:    []byte("taskrun payload"),
				trSignature:  "taskrun signature",
				trOpts:       config.StorageOpts{Key: "taskrun.uuid", PayloadFormat: formats.PayloadTypeInTotoIte6},
				ociPayload:   []byte("oci payload"),
				ociSignature: "oci signature",
				ociOpts:      config.StorageOpts{Key: "cfe4f0bf41c8", PayloadFormat: formats.PayloadTypeSimpleSigning},
			},
			wantErr: false,
		},
	}

	conn, client, err := setupConnection()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			if err != nil {
				t.Error(err)
			}

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

			ctx := context.Background()

			// test if the attestation of the **taskrun** artifact can be successfully stored into grafeas server
			// and test if payloads and signatures inside the attestation can be retrieved.
			testInterface(ctx, t, test, backend, test.args.trPayload, test.args.trSignature, test.args.trOpts)

			// test if the attestation of the **oci** artifact can be successfully stored into grafeas server
			// and test if payloads and signatures inside the attestation can be retrieved.
			testInterface(ctx, t, test, backend, test.args.ociPayload, test.args.ociSignature, test.args.ociOpts)

			// test if all occurrences generated from `StorePayload` are what we expect.
			testListOccurrences(ctx, t, backend)
		})
	}

	// close connection
	conn.Close()
}

// test attestation storage and retrieval
func testInterface(ctx context.Context, t *testing.T, test testConfig, backend Backend, payload []byte, signature string, opts config.StorageOpts) {
	if err := backend.StorePayload(ctx, payload, signature, opts); (err != nil) != test.wantErr {
		t.Errorf("Backend.StorePayload() error = %v, wantErr %v", err, test.wantErr)
	}

	// get uri
	objectIdentifier := backend.retrieveResourceURI(opts)

	// check signature
	expect_signature := map[string][]string{objectIdentifier: []string{signature}}
	got_signature, err := backend.RetrieveSignatures(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}

	if !cmp.Equal(got_signature, expect_signature) {
		t.Errorf("Wrong signature object received, got=%s", cmp.Diff(got_signature, expect_signature))
	}

	// check payload
	expect_payload := map[string]string{objectIdentifier: string(payload)}
	var got_payload map[string]string
	got_payload, err = backend.RetrievePayloads(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}

	if !cmp.Equal(got_payload, expect_payload) {
		t.Errorf("Wrong payload object received, got=%s", cmp.Diff(got_payload, expect_payload))
	}
}

// test occurrences are generated correctly
func testListOccurrences(ctx context.Context, t *testing.T, b Backend) {
	wanted := &pb.ListOccurrencesResponse{
		Occurrences: []*pb.Occurrence{
			// occurrence for taskrun
			{
				// Occurrence Name will be automatically generated by grafeas server.
				// In this fake grafeas server, we mock this behaviour by just using resource uri.
				// In the real world, the occurrence name will be in the format of `projects/<PROJECT_NAME>/occurrences/<AUTO-GENERATED-ID>`.
				// projects/my_project/occurrences/06d6e0d6-ee2b-4629-b44a-2188ac92eee4
				Name: "/apis//namespaces/foo1//bar1@uid1",
				// It's expected that the faked taskrun test does not have group version kind information.
				Resource: &pb.Resource{Uri: "/apis//namespaces/foo1//bar1@uid1"},
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
	got, err := b.client.ListOccurrences(ctx,
		&pb.ListOccurrencesRequest{
			// This is just a placeholder.
			// ProjectID doesn't matter here because we assume there is only one project in the mocked server.
			Parent: fmt.Sprintf("project/%s", b.cfg.Storage.Grafeas.ProjectID),
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	// set compare option to ignore all unexported fields of ListOccurrencesResponse struct
	// including unexported fields of the embedded structs.
	opt := cmpopts.IgnoreUnexported(
		pb.ListOccurrencesResponse{},
		pb.Occurrence{},
		pb.Resource{},
		attestationpb.Details{},
		attestationpb.Attestation{},
		attestationpb.GenericSignedAttestation{},
		commonpb.Signature{},
		commonpb.Envelope{},
		commonpb.EnvelopeSignature{},
	)
	if !cmp.Equal(got, wanted, opt) {
		t.Errorf("Wrong list of occurrences received, got=%s", cmp.Diff(got, wanted, opt))
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
	for _, v := range s.occurences {
		occurrences = append(occurrences, v)
	}
	return &pb.ListOccurrencesResponse{Occurrences: occurrences}, nil
}
