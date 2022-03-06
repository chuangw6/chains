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
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	attestationpb "github.com/grafeas/grafeas/proto/v1beta1/attestation_go_proto"
	commonpb "github.com/grafeas/grafeas/proto/v1beta1/common_go_proto"
	pb "github.com/grafeas/grafeas/proto/v1beta1/grafeas_go_proto"
	"github.com/pkg/errors"
	"github.com/tektoncd/chains/pkg/artifacts"
	"github.com/tektoncd/chains/pkg/chains/formats"
	"github.com/tektoncd/chains/pkg/config"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
)

const (
	StorageBackendGrafeas  = "grafeas"
	ProjectNameFormat = "projects/%s"
	NoteNameFormat    = "projects/%s/notes/%s"
)

// Backend is a storage backend that stores signed payloads in the TaskRun metadata as an annotation.
// It is stored as base64 encoded JSON.
type Backend struct {
	logger         *zap.SugaredLogger
	tr             *v1beta1.TaskRun
	client         pb.GrafeasV1Beta1Client
	cfg            config.Config
	occurrenceRefs []string // store occurrence IDs that are automatically generated during the time of creation
}

func NewStorageBackend(logger *zap.SugaredLogger, tr *v1beta1.TaskRun, cfg config.Config) (*Backend, error) {
	// add TypeMeta information to taskrun objects
	addTypeInformationToObject(tr)

	// build connection through grpc
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

	// connection client
	client := pb.NewGrafeasV1Beta1Client(conn)

	// create backend instance
	b := &Backend{
		logger:         logger,
		tr:             tr,
		client:         client,
		cfg:            cfg,
		occurrenceRefs: []string{},
	}

	// create note
	err = b.createNote()

	if err != nil {
		// ignore note already exisits error
		logger.Info(err)
	}

	return b, nil
}

// StorePayload implements the storage.Backend interface.
func (b *Backend) StorePayload(rawPayload []byte, signature string, opts config.StorageOpts) error {
	b.logger.Infof("Trying to store payload on TaskRun %s/%s", b.tr.Namespace, b.tr.Name)

	// We only support simplesigning for OCI images, and in-toto for taskrun.
	if opts.PayloadFormat == formats.PayloadTypeTekton || opts.PayloadFormat == formats.PayloadTypeProvenance {
		return errors.New("Container Analysis storage backend only supports for OCI images and in-toto attestations")
	}

	// step1: create occurrence request
	occurrenceReq := b.createOccurrenceRequest(rawPayload, signature, opts)
	// step2: create/store occurrence
	occurrence, err := b.client.CreateOccurrence(context.Background(), occurrenceReq)
	if err != nil {
		return err
	}

	// store reference to the newly generated occurrence for retrieve purpose
	b.occurrenceRefs = append(b.occurrenceRefs, occurrence.GetName())

	b.logger.Infof("Successfully created an occurrence %s (Occurrence_ID is automatically generated) for Taskrun %s/%s", occurrence.GetName(), b.tr.Namespace, b.tr.Name)
	return nil
}

// Retrieve payloads from container analysis and store it in a map
func (b *Backend) RetrievePayloads(opts config.StorageOpts) (map[string]string, error) {
	// initialize an empty map for result
	result := make(map[string]string)

	// get all occurrences created using this backend
	occurrences, err := b.getOccurrences()
	if err != nil {
		return nil, err
	}

	for _, occ := range occurrences {
		// get payload identifier
		name := occ.GetResource().GetUri()
		// get "Payload" field from the occurrence
		payload := occ.GetAttestation().GetAttestation().GetGenericSignedAttestation().GetSerializedPayload()

		result[name] = string(payload)
	}

	return result, nil
}

// Retrieve signatures from container analysis and store it in a map
func (b *Backend) RetrieveSignatures(opts config.StorageOpts) (map[string][]string, error) {
	// initialize an empty map for result
	result := make(map[string][]string)

	// get all occurrences created using this backend
	occurrences, err := b.getOccurrences()
	if err != nil {
		return nil, err
	}

	for _, occ := range occurrences {
		// get the Signature identifier
		name := occ.GetResource().GetUri()
		// get "Signatures" field from the occurrence DSSE envelop
		// signatures := occurrence.GetEnvelope().GetSignatures()
		signatures := occ.GetAttestation().GetAttestation().GetGenericSignedAttestation().Signatures
		// unmarshal signatures
		unmarshalSigs := []string{}
		for _, sig := range signatures {
			unmarshalSigs = append(unmarshalSigs, string(sig.GetSignature()))
		}

		result[name] = unmarshalSigs
	}

	return result, nil
}

func (b *Backend) Type() string {
	return StorageBackendGrafeas
}

// ----------------------------- Helper Functions ----------------------------
func (b *Backend) createNote() error {
	noteID := b.cfg.Storage.ContainerAnalysis.NoteID

	b.logger.Infof("Creating a note with note name %s", noteID)

	// create note request
	noteReq := &pb.CreateNoteRequest{
		Parent: b.getProjectPath(),
		NoteId: noteID,
		Note: &pb.Note{
			// Name:             b.getNotePath(),
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
		return err
	}
	return nil
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
			Uri: b.RetrieveResourceURI(opts),
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

func (b *Backend) getProjectPath() string {
	projectID := b.cfg.Storage.ContainerAnalysis.ProjectID
	return fmt.Sprintf(ProjectNameFormat, projectID)
}

func (b *Backend) getNotePath() string {
	projectID := b.cfg.Storage.ContainerAnalysis.ProjectID
	noteID := b.cfg.Storage.ContainerAnalysis.NoteID
	return fmt.Sprintf(NoteNameFormat, projectID, noteID)
}

func (b *Backend) getOccurrences() ([]*pb.Occurrence, error) {
	result := []*pb.Occurrence{}

	for _, occName := range b.occurrenceRefs {
		getOCCReq := &pb.GetOccurrenceRequest{
			Name: occName,
		}
		occ, error := b.client.GetOccurrence(context.Background(), getOCCReq)
		if error != nil {
			return nil, error
		}
		result = append(result, occ)
	}

	return result, nil
}

// addTypeInformationToObject adds TypeMeta information to a runtime.Object based upon the loaded scheme.Scheme
// inspired by: https://github.com/kubernetes/cli-runtime/blob/v0.19.2/pkg/printers/typesetter.go#L41
// Souce: https://github.com/kubernetes/client-go/issues/308#issuecomment-700099260
func addTypeInformationToObject(obj runtime.Object) error {
	gvks, _, err := scheme.Scheme.ObjectKinds(obj)
	if err != nil {
		return fmt.Errorf("missing apiVersion or kind and cannot assign it; %w", err)
	}

	for _, gvk := range gvks {
		if len(gvk.Kind) == 0 {
			continue
		}
		if len(gvk.Version) == 0 || gvk.Version == runtime.APIVersionInternal {
			continue
		}
		obj.GetObjectKind().SetGroupVersionKind(gvk)
		break
	}

	return nil
}

func (b *Backend) RetrieveResourceURI(opts config.StorageOpts) string {
	var resourceURI string

	if opts.PayloadFormat == formats.PayloadTypeSimpleSigning {
		// for oci artifact
		resourceURI = b.RetrieveOCIURI(opts)
	} else {
		// for taskrun artifact
		resourceURI = fmt.Sprintf("/apis/%s/namespaces/%s/%s/%s@%s",
			b.tr.GroupVersionKind().GroupVersion().String(),
			b.tr.Namespace,
			b.tr.Kind,
			b.tr.Name,
			string(b.tr.UID),
		)
	}
	return resourceURI
}

// Given the TaskRun, retrieve the OCI image's URL.
func (b *Backend) RetrieveOCIURI(opts config.StorageOpts) string {
	images := artifacts.ExtractOCIImagesFromResults(b.tr, b.logger)

	for _, image := range images {
		ref := image.(name.Digest)
		// for oci image, the key in StorageOpts will be the first 12 chars of digest
		digestKey := strings.TrimPrefix(ref.DigestStr(), "sha256:")[:12]

		if digestKey == opts.Key {
			return ref.Name()
		}
	}

	return ""
}
