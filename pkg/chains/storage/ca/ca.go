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

// TODO: Decide project, NoteID and OccurrenceID
// TODO: Log more messages about storing attestation to containeranalysis
// TODO: Add more comments
// TODO: (design proposal) Authenticate to Google Cloud services from the code using Workload Identity.
// TODO: Add test file
package ca

import (
	"context"
	"crypto/tls"
	"fmt"

	attestationpb "github.com/grafeas/grafeas/proto/v1beta1/attestation_go_proto"
	commonpb "github.com/grafeas/grafeas/proto/v1beta1/common_go_proto"
	pb "github.com/grafeas/grafeas/proto/v1beta1/grafeas_go_proto"
	"github.com/tektoncd/chains/pkg/config"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

const (
	StorageBackendCA     = "containeranalysis"
	ProjectNameFormat    = "projects/%s"
	NoteNameFormat       = "projects/%s/notes/%s"
	OccurrenceNameFormat = "projects/%s/occurrences/%s"
	PayloadNameFormat    = "taskrun-%s-%s/%s.payload"
	SignatureNameFormat  = "taskrun-%s-%s/%s.signature"
)

// Backend is a storage backend that stores signed payloads in the TaskRun metadata as an annotation.
// It is stored as base64 encoded JSON.
type Backend struct {
	logger *zap.SugaredLogger
	tr     *v1beta1.TaskRun
	client pb.GrafeasV1Beta1Client
}

func NewStorageBackend(logger *zap.SugaredLogger, tr *v1beta1.TaskRun) (*Backend, error) {
	// ---------------- connection -----------
	// Requires `gcloud auth application-default login` to work locally
	ctx := context.Background()
	creds, err := oauth.NewApplicationDefault(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial("dns:///containeranalysis.googleapis.com",
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})),
		grpc.WithDefaultCallOptions(grpc.PerRPCCredentials(creds)),
	)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// -------------- create backend instance -------------
	client := pb.NewGrafeasV1Beta1Client(conn)

	return &Backend{
		logger: logger,
		tr:     tr,
		client: client,
	}, nil
}

// StorePayload implements the storage.Backend interface.
func (b *Backend) StorePayload(rawPayload []byte, signature string, opts config.StorageOpts) error {
	projectPath, notePath, occurrencePath := b.getConfig()

	// --------------------------- 1. Creating Note ----------------------------
	// step1: create note request
	noteReq := b.createNoteRequest(projectPath, notePath, signature)

	// step2: create/store note
	_, err := b.client.CreateNote(context.Background(), noteReq)
	if err != nil {
		return err
	}

	// ------------------------- 2. Creating Occurrence --------------------------
	// step3: create occurrence request
	occurrenceReq := b.createOccurrenceRequest(projectPath, notePath, occurrencePath, rawPayload, signature)

	// step4: create/store occurrence
	_, err = b.client.CreateOccurrence(context.Background(), occurrenceReq)
	if err != nil {
		return err
	}

	return nil
}

// Retrieve payloads from container analysis and store it in a map
func (b *Backend) RetrievePayloads(opts config.StorageOpts) (map[string]string, error) {
	// initialize an empty map for result
	result := make(map[string]string)

	// get occurrence using client
	occurrence, err := b.getOccurrence()
	if err != nil {
		return nil, err
	}

	// get "Payload" field from the occurrence DSSE envelop
	payload := occurrence.GetEnvelope().GetPayload()
	// give the payload a name
	payloadName := b.getPayloadName(opts)

	result[payloadName] = string(payload)
	return result, nil
}

// Retrieve signatures from container analysis and store it in a map
func (b *Backend) RetrieveSignatures(opts config.StorageOpts) (map[string][]string, error) {
	// initialize an empty map for result
	result := make(map[string][]string)

	// get occurrence using client
	occurrence, err := b.getOccurrence()
	if err != nil {
		return nil, err
	}

	// get "Signatures" field from the occurrence DSSE envelop
	signatures := occurrence.GetEnvelope().GetSignatures()
	// unmarshal signatures
	unmarshalSigs := []string{}
	for _, sig := range signatures {
		unmarshalSigs = append(unmarshalSigs, string(sig.GetSig()))
	}
	// give the Signature a name
	signaturesName := b.getSigName(opts)

	result[signaturesName] = unmarshalSigs
	return result, nil
}

func (b *Backend) Type() string {
	return StorageBackendCA
}

// ---------------------------------------------------------------------------
// ----------------------------- Helper Functions ----------------------------
// ---------------------------------------------------------------------------

// Placeholder: get project ID, set note path and occurrence path
func (b *Backend) getConfig() (string, string, string) {
	providerProjectID := "provider_example"
	projectPath := fmt.Sprintf(ProjectNameFormat, providerProjectID)

	noteID := "noteID_example"
	notePath := fmt.Sprintf(NoteNameFormat, providerProjectID, noteID)

	occurrenceID := "occurrenceID_example"
	occurrencePath := fmt.Sprintf(OccurrenceNameFormat, providerProjectID, occurrenceID)
	return projectPath, notePath, occurrencePath
}

func (b *Backend) getPayloadName(opts config.StorageOpts) string {
	return fmt.Sprintf(PayloadNameFormat, b.tr.Namespace, b.tr.Name, opts.Key)
}

func (b *Backend) getSigName(opts config.StorageOpts) string {
	return fmt.Sprintf(SignatureNameFormat, b.tr.Namespace, b.tr.Name, opts.Key)
}

func (b *Backend) getOccurrence() (*pb.Occurrence, error) {
	_, _, occurrencePath := b.getConfig()

	getOCCReq := &pb.GetOccurrenceRequest{
		Name: occurrencePath,
	}

	return b.client.GetOccurrence(context.Background(), getOCCReq)
}

func (b *Backend) createNoteRequest(projectPath string, notePath string, signature string) *pb.CreateNoteRequest {
	return &pb.CreateNoteRequest{
		Parent: projectPath,
		NoteId: notePath,
		Note: &pb.Note{
			Name:             notePath,
			ShortDescription: "An attestation note",
			Kind:             commonpb.NoteKind_ATTESTATION,
			Type: &pb.Note_AttestationAuthority{
				AttestationAuthority: &attestationpb.Authority{
					Hint: &attestationpb.Authority_Hint{
						HumanReadableName: "Tekton Chains",
					},
				},
			},
		},
	}
}

func (b *Backend) createOccurrenceRequest(projectPath string, notePath string, occurrencePath string, payload []byte, signature string) *pb.CreateOccurrenceRequest {
	occurrenceDetails := &pb.Occurrence_Attestation{
		Attestation: &attestationpb.Details{
			Attestation: &attestationpb.Attestation{
				Signature: &attestationpb.Attestation_GenericSignedAttestation{
					GenericSignedAttestation: &attestationpb.GenericSignedAttestation{
						ContentType:       attestationpb.GenericSignedAttestation_CONTENT_TYPE_UNSPECIFIED, // TODO: correct?
						SerializedPayload: payload,
						Signatures: []*commonpb.Signature{
							{
								Signature: []byte(signature),
								// TODO: Do we need to add PublicKeyId field here?
							},
						},
					},
				},
			},
		},
	}

	envelope := &commonpb.Envelope{
		Payload:     payload,
		PayloadType: "in-toto attestations containing a slsa.dev/provenance predicate",
		Signatures: []*commonpb.EnvelopeSignature{
			{
				Sig: []byte(signature),
				// TODO: Do we need to add Keyid field here?
				// "Optional, unauthenticated hint indicating what key and algorithm was used to sign the message."
				// https://github.com/secure-systems-lab/dsse/blob/master/protocol.md#signature-definition
			},
		},
	}

	occurrence := &pb.Occurrence{
		Name: projectPath,
		Resource: &pb.Resource{
			Name: string(b.tr.UID),
			Uri:  "tekton://chains.tekton.dev/taskruns/" + string(b.tr.UID),
		},
		NoteName: notePath,
		Kind:     commonpb.NoteKind_ATTESTATION,
		// TODO: do we want to add CreateTime, UpdateTime etc. info here?
		// ASK: will chains actually update an occurrence frequently?
		// if so, where does it do it?
		Details:  occurrenceDetails,
		Envelope: envelope,
	}

	occurrenceRequest := &pb.CreateOccurrenceRequest{
		Parent:     projectPath,
		Occurrence: occurrence,
	}

	return occurrenceRequest
}
