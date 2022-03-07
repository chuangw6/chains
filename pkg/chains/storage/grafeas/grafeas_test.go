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
	"github.com/tektoncd/chains/pkg/chains/formats"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			client, err := setupConnection()
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

			// test taskrun
			testInterface(t, test, backend, test.args.trPayload, test.args.trSignature, test.args.trOpts)
			// test oci
			testInterface(t, test, backend, test.args.ociPayload, test.args.ociSignature, test.args.ociOpts)

		})
	}
}

func testInterface(t *testing.T, test testConfig, backend Backend, payload []byte, signature string, opts config.StorageOpts) {
	if err := backend.StorePayload(payload, signature, opts); (err != nil) != test.wantErr {
		t.Errorf("Backend.StorePayload() error = %v, wantErr %v", err, test.wantErr)
	}

	// get uri
	objectIdentifier := backend.retrieveResourceURI(opts)

	// check signature
	expect_signature := map[string][]string{objectIdentifier: []string{signature}}
	got_signature, err := backend.RetrieveSignatures(opts)
	if err != nil {
		t.Fatal(err)
	}

	if !cmp.Equal(got_signature, expect_signature) {
		t.Errorf("Wrong signature object received, got=%s", cmp.Diff(got_signature, expect_signature))
	}

	// check payload
	expect_payload := map[string]string{objectIdentifier: string(payload)}
	var got_payload map[string]string
	got_payload, err = backend.RetrievePayloads(opts)
	if err != nil {
		t.Fatal(err)
	}

	if !cmp.Equal(got_payload, expect_payload) {
		t.Errorf("Wrong payload object received, got=%s", cmp.Diff(got_payload, expect_payload))
	}
}

func setupConnection() (pb.GrafeasV1Beta1Client, error) {
	serv := grpc.NewServer()
	pb.RegisterGrafeasV1Beta1Server(serv, &grafeasServer)

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, err
	}

	go serv.Serve(lis)

	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	client := pb.NewGrafeasV1Beta1Client(conn)
	return client, nil
}

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
