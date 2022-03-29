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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	pb "github.com/grafeas/grafeas/proto/v1/grafeas_go_proto"
	"github.com/pkg/errors"
	"github.com/tektoncd/chains/pkg/artifacts"
	"github.com/tektoncd/chains/pkg/chains/formats"
	"github.com/tektoncd/chains/pkg/config"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

const (
	StorageBackendGrafeas = "grafeas"
	projectNameFormat     = "projects/%s"
	noteNameFormat        = "projects/%s/notes/%s"
)

// Backend is a storage backend that stores signed payloads in the storage that
// is built on the top of grafeas i.e. container analysis.
type Backend struct {
	logger *zap.SugaredLogger
	tr     *v1beta1.TaskRun
	client pb.GrafeasClient
	cfg    config.Config
}

// NewStorageBackend returns a new Grafeas StorageBackend that stores signatures in a Grafeas server
func NewStorageBackend(ctx context.Context, logger *zap.SugaredLogger, tr *v1beta1.TaskRun, cfg config.Config) (*Backend, error) {
	// build connection through grpc
	// implicit uses Application Default Credentials to authenticate.
	// Requires `gcloud auth application-default login` to work locally
	creds, err := oauth.NewApplicationDefault(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, err
	}

	// TODO: make grafeas server configurable including checking if hostname is trusted
	server := "dns:///containeranalysis.googleapis.com"

	conn, err := grpc.Dial(server,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})),
		grpc.WithDefaultCallOptions(grpc.PerRPCCredentials(creds)),
	)
	if err != nil {
		return nil, err
	}

	// connection client
	client := pb.NewGrafeasClient(conn)

	// create backend instance
	return &Backend{
		logger: logger,
		tr:     tr,
		client: client,
		cfg:    cfg,
	}, nil
}

// StorePayload implements the storage.Backend interface.
func (b *Backend) StorePayload(ctx context.Context, rawPayload []byte, signature string, opts config.StorageOpts) error {
	// We only support simplesigning for OCI images, and in-toto for taskrun.
	if opts.PayloadFormat == formats.PayloadTypeTekton || opts.PayloadFormat == formats.PayloadTypeProvenance {
		return errors.New("Grafeas storage backend only supports for OCI images and in-toto attestations")
	}

	// Check if projectID is configured. If not, stop and return an error
	if b.cfg.Storage.Grafeas.ProjectID == "" {
		return errors.New("Project ID needs to be configured!")
	}

	// check if noteID is configured. If not, we give it a name as `tekton-<namespace>`
	if b.cfg.Storage.Grafeas.NoteID == "" {
		generatedNoteID := fmt.Sprintf("tekton-%s", b.tr.GetNamespace())
		b.cfg.Storage.Grafeas.NoteID = generatedNoteID
	}

	b.logger.Infof("Trying to store payload on TaskRun %s/%s", b.tr.Namespace, b.tr.Name)

	// step1: create note
	if _, err := b.createNote(ctx, opts); err != nil {
		return err
	}

	// step2: create occurrence
	occurrence, err := b.createOccurrence(ctx, rawPayload, signature, opts)
	if err != nil {
		return err
	}

	b.logger.Infof("Successfully created an occurrence %s for Taskrun %s/%s", occurrence.GetName(), b.tr.Namespace, b.tr.Name)
	return nil
}

// Retrieve payloads from grafeas server and store it in a map
func (b *Backend) RetrievePayloads(ctx context.Context, opts config.StorageOpts) (map[string]string, error) {
	// initialize an empty map for result
	result := make(map[string]string)

	// get all occurrences created using this backend
	occurrences, err := b.getOccurrences(ctx)
	if err != nil {
		return nil, err
	}

	for _, occ := range occurrences {
		// get payload identifier
		name := occ.GetResourceUri()
		// get "Payload" field from the occurrence
		payload := occ.GetAttestation().GetSerializedPayload()

		result[name] = string(payload)
	}

	return result, nil
}

// Retrieve signatures from grafeas server and store it in a map
func (b *Backend) RetrieveSignatures(ctx context.Context, opts config.StorageOpts) (map[string][]string, error) {
	// initialize an empty map for result
	result := make(map[string][]string)

	// get all occurrences created using this backend
	occurrences, err := b.getOccurrences(ctx)
	if err != nil {
		return nil, err
	}

	for _, occ := range occurrences {
		// get the Signature identifier
		name := occ.GetResourceUri()
		// get "Signatures" field from the occurrence
		signatures := occ.GetEnvelope().GetSignatures()
		// unmarshal signatures
		unmarshalSigs := []string{}
		for _, sig := range signatures {
			unmarshalSigs = append(unmarshalSigs, string(sig.GetSig()))
		}

		result[name] = unmarshalSigs
	}

	return result, nil
}

func (b *Backend) Type() string {
	return StorageBackendGrafeas
}

// ----------------------------- Helper Functions ----------------------------
func (b *Backend) createNote(ctx context.Context, opts config.StorageOpts) (*pb.Note, error) {
	// TODO: differentiate build note and attestation note
	noteID := b.cfg.Storage.Grafeas.NoteID

	b.logger.Infof("Creating a note with note name %s", noteID)

	// for oci image: AttestationNote
	if opts.PayloadFormat == formats.PayloadTypeSimpleSigning {
		return b.client.CreateNote(ctx,
			&pb.CreateNoteRequest{
				Parent: b.getProjectPath(),
				NoteId: noteID,
				Note: &pb.Note{
					ShortDescription: "OCI Image Attestation Note",
					Type: &pb.Note_Attestation{
						Attestation: &pb.AttestationNote{
							Hint: &pb.AttestationNote_Hint{
								HumanReadableName: "This attestation note was generated by Tekton Chains",
							},
						},
					},
				},
			},
		)
	}

	// for taskrun: BuildNote
	return b.client.CreateNote(ctx,
		&pb.CreateNoteRequest{
			Parent: b.getProjectPath(),
			NoteId: noteID,
			Note: &pb.Note{
				ShortDescription: "Build Provenance Note",
				Type: &pb.Note_Build{
					Build: &pb.BuildNote{
						BuilderVersion: b.tr.GetGroupVersionKind().GroupVersion().String(),
					},
				},
				RelatedUrl: []*pb.RelatedUrl{
					// TODO: log url
				},
			},
		},
	)
}

// create occurrence
// - Occurrence_Attestation for OCI
// - Occurrence_Build for TaskRun
func (b *Backend) createOccurrence(ctx context.Context, payload []byte, signature string, opts config.StorageOpts) (*pb.Occurrence, error) {
	uri, err := b.getResourceURI(opts)
	if err != nil {
		return nil, err
	}

	// for oci image: Occurrence_Attestation
	if opts.PayloadFormat == formats.PayloadTypeSimpleSigning {
		occurrenceDetails := &pb.Occurrence_Attestation{
			Attestation: &pb.AttestationOccurrence{
				SerializedPayload: payload,
				Signatures: []*pb.Signature{
					{
						Signature: []byte(signature),
						// TODO: currently we only support storing kms keyID, will add other keys' ids later i.e. k8s secret, fulcio
						PublicKeyId: b.cfg.Signers.KMS.KMSRef,
					},
				},
			},
		}
		envelope := &pb.Envelope{
			Payload:     payload,
			PayloadType: "simplesigning",
			Signatures: []*pb.EnvelopeSignature{
				{
					Sig: []byte(signature),
					// TODO: currently we only support storing kms keyID, will add other keys' ids later i.e. k8s secret, fulcio
					Keyid: b.cfg.Signers.KMS.KMSRef,
				},
			},
		}

		return b.client.CreateOccurrence(ctx,
			&pb.CreateOccurrenceRequest{
				Parent: b.getProjectPath(),
				Occurrence: &pb.Occurrence{
					ResourceUri: uri,
					NoteName:    b.getNotePath(),
					Details:     occurrenceDetails,
					Envelope:    envelope,
				},
			},
		)
	}

	// for taskrun: Occurrence_Build
	var statement *pb.InTotoStatement

	// TODO: slsa provenance version differences: chains v0.2, grafeas v0.1
	if err := json.Unmarshal(payload, statement); err != nil {
		return nil, err
	}

	occurrenceDetails := &pb.Occurrence_Build{
		Build: &pb.BuildOccurrence{
			IntotoStatement: statement,
		},
	}

	envelope := &pb.Envelope{
		Payload:     payload,
		PayloadType: "in-toto attestations containing a slsa.dev/provenance predicate",
		Signatures: []*pb.EnvelopeSignature{
			{
				Sig:   []byte(signature),
				Keyid: b.cfg.Signers.KMS.KMSRef,
			},
		},
	}

	return b.client.CreateOccurrence(ctx,
		&pb.CreateOccurrenceRequest{
			Parent: b.getProjectPath(),
			Occurrence: &pb.Occurrence{
				ResourceUri: uri,
				NoteName:    b.getNotePath(),
				Details:     occurrenceDetails,
				Envelope:    envelope,
			},
		},
	)
}

func (b *Backend) getProjectPath() string {
	projectID := b.cfg.Storage.Grafeas.ProjectID
	return fmt.Sprintf(projectNameFormat, projectID)
}

func (b *Backend) getNotePath() string {
	projectID := b.cfg.Storage.Grafeas.ProjectID
	noteID := b.cfg.Storage.Grafeas.NoteID
	return fmt.Sprintf(noteNameFormat, projectID, noteID)
}

// retrieve all occurrences created under a taskrun by filtering resource URI
func (b *Backend) getOccurrences(ctx context.Context) ([]*pb.Occurrence, error) {
	// step 1: get all resource URIs created under the taskrun
	uriFilters := []string{}
	uriFilters = append(uriFilters, b.retrieveAllOCIURIs()...)
	uriFilters = append(uriFilters, b.getTaskRunURI())

	// step 2: find all occurrences by using ListOccurrences filters
	occs, err := b.findOccurrencesForCriteria(ctx, b.getProjectPath(), uriFilters)
	if err != nil {
		return nil, err
	}
	return occs, nil
}

// find all occurrences based on a number of criteria
// - current criteria we use are just project name and resource uri
// - we can add more criteria later if we want i.e. occurrence Kind, severity and PageSize etc.
func (b *Backend) findOccurrencesForCriteria(ctx context.Context, projectPath string, resourceURIs []string) ([]*pb.Occurrence, error) {
	var uriFilters []string
	for _, url := range resourceURIs {
		uriFilters = append(uriFilters, fmt.Sprintf("resourceUrl=%q", url))
	}

	occurences, err := b.client.ListOccurrences(ctx,
		&pb.ListOccurrencesRequest{
			Parent: projectPath,
			Filter: strings.Join(uriFilters, " OR "),
		},
	)

	if err != nil {
		return nil, err
	}
	return occurences.GetOccurrences(), nil
}

// get resource uri based on the configured payload format that helps differentiate artifact type as well.
func (b *Backend) getResourceURI(opts config.StorageOpts) (string, error) {
	switch opts.PayloadFormat {
	case formats.PayloadTypeSimpleSigning:
		return b.getOCIURI(opts), nil
	case formats.PayloadTypeInTotoIte6:
		return b.getTaskRunURI(), nil
	default:
		return "", errors.New("Invalid payload format. Only in-toto and simplesigning are supported.")
	}
}

// get resource uri for a taskrun in the format of namespace-scoped resource uri
// `/apis/GROUP/VERSION/namespaces/NAMESPACE/RESOURCETYPE/NAME``
// see more details here https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-uris
func (b *Backend) getTaskRunURI() string {
	return fmt.Sprintf("/apis/%s/namespaces/%s/%s/%s@%s",
		b.tr.GetGroupVersionKind().GroupVersion().String(),
		b.tr.GetNamespace(),
		b.tr.GetGroupVersionKind().Kind,
		b.tr.GetName(),
		string(b.tr.UID),
	)
}

// get resource uri for an oci image in the format of `IMAGE_URL@IMAGE_DIGEST`
func (b *Backend) getOCIURI(opts config.StorageOpts) string {
	imgs := b.retrieveAllOCIURIs()
	for _, img := range imgs {
		// get digest part of the image representation
		digest := strings.Split(img, "sha256:")[1]

		// for oci image, the key in StorageOpts will be the first 12 chars of digest
		// so we want to compare
		digestKey := digest[:12]
		if digestKey == opts.Key {
			return img
		}
	}
	return ""
}

// get the uri of all images for a specific taskrun in the format of `IMAGE_URL@IMAGE_DIGEST`
func (b *Backend) retrieveAllOCIURIs() []string {
	result := []string{}
	images := artifacts.ExtractOCIImagesFromResults(b.tr, b.logger)

	for _, image := range images {
		ref := image.(name.Digest)
		result = append(result, ref.Name())
	}

	return result
}
