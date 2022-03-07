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
	"testing"

	"github.com/tektoncd/chains/pkg/chains/formats"

	"github.com/tektoncd/chains/pkg/config"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
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

func TestBackend_StorePayload(t *testing.T) {
	tests := []testConfig{
		// test 1
		{
			name: "no error, simplesining and intoto",
			args: args{
				tr: &v1beta1.TaskRun{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "foo",
						Name:      "bar",
						UID:       types.UID("uid"),
					},
					Status: v1beta1.TaskRunStatus{
						TaskRunStatusFields: v1beta1.TaskRunStatusFields{
							TaskRunResults: []v1beta1.TaskRunResult{
								{Name: "IMAGE_DIGEST", Value: "sha256:cfx4f0bf41c80609214f9b8ec0408b1afb28b3ced343b944aaa05d47caba3e00"},
								{Name: "IMAGE_URL", Value: "gcr.io/test/kaniko-chains1"},
								{Name: "IMAGE_DIGEST", Value: "sha256:xxx4f0bf41c80609214f9b8ec0408b1afb28b3ced343b944aaa05d47caba3e00"},
								{Name: "IMAGE_URL", Value: "gcr.io/test/kaniko-chains2"},
							},
						},
					},
				},
				trPayload:    []byte("taskrun payload"),
				trSignature:  "taskrun signature",
				trOpts:       config.StorageOpts{Key: "taskrun.uuid", PayloadFormat: formats.PayloadTypeInTotoIte6},
				ociPayload:   []byte("oci payload"),
				ociSignature: "oci signature",
				ociOpts:      config.StorageOpts{Key: "oci.uuid", PayloadFormat: formats.PayloadTypeSimpleSigning},
			},
			wantErr: false,
		},
		// test 2
		{
			name: "error, tekton format",
			args: args{
				tr: &v1beta1.TaskRun{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "foo",
						Name:      "bar",
						UID:       types.UID("uid"),
					},
				},
				trOpts: config.StorageOpts{Key: "taskrun.uuid", PayloadFormat: formats.PayloadTypeTekton},
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			backend := Backend{
				logger: logtesting.TestLogger(t),
				tr:     test.args.tr,
				client: , // TODO
				// cfg : config.Config{
				// 	Storage: config.StorageConfigs{
				// 		Grafeas: config.GrafeasConfig{
				// 			ProjectID: "test-project",
				// 			NoteID:    "test-note",
				// 			Server: "test-server",
				// 		},
				// 	},
				// },
			}

			// test taskrun
			testInterface(t, &test, &backend, test.args.trPayload, test.args.trSignature, test.args.trOpts)
			// test oci
			testInterface(t, &test, &backend, test.args.ociPayload, test.args.ociSignature, test.args.ociOpts)
		})
	}
}

func testInterface(t *testing.T, test *testConfig, backend *Backend, payload []byte, signature string, opts config.StorageOpts) {
	if err := backend.StorePayload(payload, signature, opts); (err != nil) != test.wantErr {
		t.Errorf("Backend.StorePayload() error = %v, wantErr %v", err, test.wantErr)
	}

	// get uri
	objectIdentifier := backend.retrieveResourceURI(opts)

	// check signature
	got_signature, err := backend.RetrieveSignatures(opts)
	if err != nil {
		t.Fatal(err)
	}
	if got_signature[objectIdentifier][0] != signature {
		t.Errorf("wrong signature, expected %q, got %q", signature, got_signature[objectIdentifier][0])
	}

	// check payload
	var got_payload map[string]string
	got_payload, err = backend.RetrievePayloads(opts)
	if err != nil {
		t.Fatal(err)
	}
	if got_payload[objectIdentifier] != string(payload) {
		t.Errorf("wrong payload, expected %s, got %s", payload, got_payload[objectIdentifier])
	}
}
