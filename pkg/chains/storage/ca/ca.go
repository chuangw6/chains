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

package ca

import (
	"context"
	"crypto/tls"
	"fmt"

	attestationpb "github.com/grafeas/grafeas/proto/v1beta1/attestation_go_proto"
	commonpb "github.com/grafeas/grafeas/proto/v1beta1/common_go_proto"
	pb "github.com/grafeas/grafeas/proto/v1beta1/grafeas_go_proto"
	"github.com/pkg/errors"
	"github.com/tektoncd/chains/pkg/chains/formats"
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
	OccurrenceNameFormat = "projects/%s/occurrences/taskrun-%s-%s-%s"
	PayloadNameFormat    = "taskrun-%s-%s/%s.payload"
	SignatureNameFormat  = "taskrun-%s-%s/%s.signature"
)

// Backend is a storage backend that stores signed payloads in the TaskRun metadata as an annotation.
// It is stored as base64 encoded JSON.
type Backend struct {
	logger  *zap.SugaredLogger
	tr      *v1beta1.TaskRun
	client  pb.GrafeasV1Beta1Client
	cfg     config.Config
	occName string
}

func NewStorageBackend(logger *zap.SugaredLogger, tr *v1beta1.TaskRun, cfg config.Config) (*Backend, error) {
	// ---------------- connection -----------
	// implicit uses Application Default Credentials to authenticate.
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
	// defer conn.Close()

	// -------------- create backend instance -------------
	client := pb.NewGrafeasV1Beta1Client(conn)

	return &Backend{
		logger: logger,
		tr:     tr,
		client: client,
		cfg:    cfg,
	}, nil
}

// StorePayload implements the storage.Backend interface.
func (b *Backend) StorePayload(rawPayload []byte, signature string, opts config.StorageOpts) error {
	b.logger.Infof("Trying to store payload on TaskRun %s/%s", b.tr.Namespace, b.tr.Name)
	// create note first
	b.createNote()

	// We only support simplesigning for OCI images, and in-toto for taskrun.
	if opts.PayloadFormat == formats.PayloadTypeTekton {
		return errors.New("Container Analysis storage backend only supports for OCI images and in-toto attestations")
	}

	// step1: create occurrence request
	occurrenceReq := b.createOccurrenceRequest(rawPayload, signature, opts)
	// step2: create/store occurrence
	occurrence, err := b.client.CreateOccurrence(context.Background(), occurrenceReq)
	if err != nil {
		return err
	}

	b.occName = occurrence.GetName()

	b.logger.Infof("Successfully created an occurrence %s (Occurrence_ID is automatically generated) for Taskrun %s/%s", b.occName, b.tr.Namespace, b.tr.Name)
	return nil
}

// Retrieve payloads from container analysis and store it in a map
func (b *Backend) RetrievePayloads(opts config.StorageOpts) (map[string]string, error) {
	// initialize an empty map for result
	result := make(map[string]string)

	// get occurrence using client
	occurrence, err := b.getOccurrence(opts)
	if err != nil {
		return nil, err
	}

	// get "Payload" field from the occurrence DSSE envelop
	payload := occurrence.GetAttestation().GetAttestation().GetGenericSignedAttestation().GetSerializedPayload()
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
	occurrence, err := b.getOccurrence(opts)
	if err != nil {
		return nil, err
	}

	// get "Signatures" field from the occurrence DSSE envelop
	// signatures := occurrence.GetEnvelope().GetSignatures()
	signatures := occurrence.GetAttestation().GetAttestation().GetGenericSignedAttestation().Signatures
	// unmarshal signatures
	unmarshalSigs := []string{}
	for _, sig := range signatures {
		unmarshalSigs = append(unmarshalSigs, string(sig.GetSignature()))
	}
	// give the Signature a name
	signaturesName := b.getSigName(opts)

	result[signaturesName] = unmarshalSigs
	return result, nil
}

func (b *Backend) Type() string {
	return StorageBackendCA
}

// ----------------------------- Helper Functions ----------------------------
func (b *Backend) createNote() {
	projectPath := b.getProjectPath()
	noteID := b.cfg.Storage.ContainerAnalysis.NoteID
	notePath := b.getNotePath()

	b.logger.Infof("Creating a note - %s", notePath)

	// create note request
	noteReq := &pb.CreateNoteRequest{
		Parent: projectPath,
		NoteId: noteID,
		Note: &pb.Note{
			Name:             notePath,
			ShortDescription: "An attestation note",
			Kind:             commonpb.NoteKind_ATTESTATION,
			Type: &pb.Note_AttestationAuthority{
				AttestationAuthority: &attestationpb.Authority{
					Hint: &attestationpb.Authority_Hint{
						HumanReadableName: "This note was auto-generated by Tekton Chains",
					},
				},
			},
		},
	}

	// store note
	_, err := b.client.CreateNote(context.Background(), noteReq)

	if err != nil {
		// noteID already exisits
		b.logger.Warn(err)
	}
}

func (b *Backend) createOccurrenceRequest(payload []byte, signature string, opts config.StorageOpts) *pb.CreateOccurrenceRequest {
	occurrenceDetails := &pb.Occurrence_Attestation{
		Attestation: &attestationpb.Details{
			Attestation: &attestationpb.Attestation{
				Signature: &attestationpb.Attestation_GenericSignedAttestation{
					GenericSignedAttestation: &attestationpb.GenericSignedAttestation{
						// Uspecified ContentType because we have simplesigning for OCI, In-toto for TaskRun
						ContentType:       attestationpb.GenericSignedAttestation_CONTENT_TYPE_UNSPECIFIED,
						SerializedPayload: payload,
						Signatures: []*commonpb.Signature{
							{
								Signature:   []byte(signature),
								PublicKeyId: b.cfg.Signers.KMS.KMSRef,
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
				Sig:   []byte(signature),
				Keyid: b.cfg.Signers.KMS.KMSRef,
			},
		},
	}

	occurrence := &pb.Occurrence{
		Resource: &pb.Resource{
			// namespace-scoped resource
			// https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-uris
			Uri: fmt.Sprintf("/apis/%s/namespaces/%s/%s/%s",
				b.tr.GroupVersionKind().GroupVersion().String(),
				b.tr.Namespace,
				b.tr.Kind,
				b.tr.Name),
		},
		NoteName: b.getNotePath(),
		Details:  occurrenceDetails,
		Envelope: envelope,
	}

	occurrenceRequest := &pb.CreateOccurrenceRequest{
		Parent:     b.getProjectPath(),
		Occurrence: occurrence,
	}

	return occurrenceRequest
}

func (b *Backend) getOccurrence(opts config.StorageOpts) (*pb.Occurrence, error) {
	getOCCReq := &pb.GetOccurrenceRequest{
		Name: b.occName,
	}

	return b.client.GetOccurrence(context.Background(), getOCCReq)
}

func (b *Backend) getProjectPath() string {
	projectID := b.cfg.Storage.ContainerAnalysis.ProjectID
	return fmt.Sprintf(ProjectNameFormat, projectID)
}

func (b *Backend) getNotePath() string {
	projectID := b.cfg.Storage.ContainerAnalysis.ProjectID
	noteID := b.cfg.Storage.ContainerAnalysis.NoteID
	return fmt.Sprintf(NoteNameFormat, projectID, noteID)
}

func (b *Backend) getOccurrencePath(opts config.StorageOpts) string {
	projectID := b.cfg.Storage.ContainerAnalysis.ProjectID
	return fmt.Sprintf(OccurrenceNameFormat, projectID, b.tr.Namespace, b.tr.Name, opts.Key)
}

func (b *Backend) getPayloadName(opts config.StorageOpts) string {
	return fmt.Sprintf(PayloadNameFormat, b.tr.Namespace, b.tr.Name, opts.Key)
}

func (b *Backend) getSigName(opts config.StorageOpts) string {
	return fmt.Sprintf(SignatureNameFormat, b.tr.Namespace, b.tr.Name, opts.Key)
}
