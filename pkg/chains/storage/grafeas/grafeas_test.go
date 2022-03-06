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

func TestBackend_StorePayload(t *testing.T) {

	type args struct {
		tr        *v1beta1.TaskRun
		signed    []byte
		signature string
		opts      config.StorageOpts
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "no error, intoto",
			args: args{
				tr: &v1beta1.TaskRun{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "foo",
						Name:      "bar",
						UID:       types.UID("uid"),
					},
				},
				signed:    []byte("signed"),
				signature: "signature",
				opts:      config.StorageOpts{Key: "foo.uuid", PayloadFormat: formats.PayloadTypeSimpleSigning},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logtesting.TestLogger(t)
			tr := tt.args.tr
			cfg := config.Config{
				Storage: config.StorageConfigs{
					Grafeas: config.GrafeasConfig{
						ProjectID: "chuangw-test",
						NoteID:    "chuangw-test-note",
					},
				},
			}

			b, err := NewStorageBackend(logger, tr, cfg)

			if err != nil {
				t.Fatal(err)
			}

			if err := b.StorePayload(tt.args.signed, tt.args.signature, tt.args.opts); (err != nil) != tt.wantErr {
				t.Errorf("Backend.StorePayload() error = %v, wantErr %v", err, tt.wantErr)
			}

			objectIdentifier := b.retrieveResourceURI(tt.args.opts)
			got_signature, err := b.RetrieveSignatures(tt.args.opts)
			if err != nil {
				t.Fatal(err)
			}
			if got_signature[objectIdentifier][0] != tt.args.signature {
				t.Errorf("wrong signature, expected %q, got %q", tt.args.signature, got_signature[objectIdentifier][0])
			}
			var got_payload map[string]string
			got_payload, err = b.RetrievePayloads(tt.args.opts)
			if err != nil {
				t.Fatal(err)
			}
			if got_payload[objectIdentifier] != string(tt.args.signed) {
				t.Errorf("wrong payload, expected %s, got %s", tt.args.signed, got_payload[objectIdentifier])
			}
		})
	}
}
