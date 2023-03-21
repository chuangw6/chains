/*
Copyright 2022 The Tekton Authors
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

package taskrun

import (
	"context"
	"fmt"
	"time"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/tektoncd/chains/pkg/chains/formats/slsa/extract"
	"github.com/tektoncd/chains/pkg/chains/formats/slsa/internal/material"
	"github.com/tektoncd/chains/pkg/chains/objects"
	"github.com/tektoncd/chains/pkg/config"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"knative.dev/pkg/logging"
)

// BuildConfig is the custom Chains format to fill out the
// "buildConfig" section of the slsa-provenance predicate
type BuildConfig struct {
	// TaskSpec       *v1beta1.TaskSpec       `json:"taskSpec"`
	// TaskRunResults []v1beta1.TaskRunResult `json:"taskRunResults"`
	TaskSpec       interface{} `json:"taskSpec"`
	TaskRunResults interface{} `json:"taskRunResults"`
}

func GenerateAttestation(builderID string, payloadType config.PayloadType, unstructuredTr *objects.TaskRunObject, ctx context.Context) (interface{}, error) {
	// // the following 8 lines will not be needed assuming the tro is changed to be based on the unstructured object
	// dc, err := dynamicclient.NewClient()
	// if err != nil {
	// 	return nil, err
	// }
	// unstructuredTr, err := dc.Resource(objects.TaskrunResource).Namespace(tro.Namespace).Get(ctx, tro.Name, metav1.GetOptions{})
	// if err != nil {
	// 	return nil, fmt.Errorf("not able to find the taskrun: %v", err)
	// }

	// now, we need to access the specific fields of TaskRun through the unstructure object
	// 1. TaskRun.Status.TaskSpec for [predicate.BuildConfig]
	spec, found, err := unstructured.NestedFieldCopy(unstructuredTr.UnstructuredContent(), "status", "taskSpec")
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, fmt.Errorf("spec field not found on taskrun status")
	}

	// 2. TaskRun.Status.TaskResults for [predicate.BuildConfig]
	results, found, err := unstructured.NestedFieldCopy(unstructuredTr.UnstructuredContent(), "status", "taskResults")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("results not found on taskrun status")
	}

	// 3. for [predicate.Invocation]
	invo, err := reimplInvocation(unstructuredTr.Unstructured)
	if err != nil {
		return nil, err
	}

	// 4. for subjects
	logger := logging.FromContext(ctx)
	// subjects := extract.SubjectDigests(tro, logger)
	subjects, err := extract.ReimplSubjectDigests(unstructuredTr.Unstructured, logger)
	if err != nil {
		return nil, err
	}

	// 5. for materials
	// mat, err := material.Materials(tro, logger)
	// if err != nil {
	// 	return nil, err
	// }
	mat, err := material.ReimplMaterials(unstructuredTr.Unstructured, logger)
	if err != nil {
		return nil, err
	}

	// 6. for metadata
	metadata, err := reimplMetadata(unstructuredTr.Unstructured)

	att := intoto.ProvenanceStatement{
		StatementHeader: intoto.StatementHeader{
			Type:          intoto.StatementInTotoV01,
			PredicateType: slsa.PredicateSLSAProvenance,
			Subject:       subjects,
		},
		Predicate: slsa.ProvenancePredicate{
			Builder: slsa.ProvenanceBuilder{
				ID: builderID,
			},
			// TBD, current discussion sounds like this field should be configurable through configmap.
			// BuildType: fmt.Sprintf("https://chains.tekton.dev/format/%v/type/%s", payloadType, tro.GetGVK()),
			BuildType: fmt.Sprintf("https://chains.tekton.dev/format/%v/type/%s", payloadType, unstructuredTr.GroupVersionKind().String()),
			// Invocation:  invocation(tro),
			Invocation: invo,
			// BuildConfig: BuildConfig{TaskSpec: tro.Status.TaskSpec, TaskRunResults: tro.Status.TaskRunResults},
			BuildConfig: BuildConfig{TaskSpec: spec, TaskRunResults: results},
			// Metadata:    slsav1.Metadata(tro),
			Metadata: metadata,

			Materials: mat,
		},
	}
	return att, nil
}

// // invocation describes the event that kicked off the build
// // we currently don't set ConfigSource because we don't know
// // which material the Task definition came from
// func invocation(tro *objects.TaskRunObject) slsa.ProvenanceInvocation {
// 	i := slsa.ProvenanceInvocation{}
// 	if p := tro.Status.Provenance; p != nil && p.ConfigSource != nil {
// 		i.ConfigSource = slsa.ConfigSource{
// 			URI:        p.ConfigSource.URI,
// 			Digest:     p.ConfigSource.Digest,
// 			EntryPoint: p.ConfigSource.EntryPoint,
// 		}
// 	}
// 	i.Parameters = invocationParams(tro)
// 	env := invocationEnv(tro)
// 	if len(env) > 0 {
// 		i.Environment = env
// 	}
// 	return i
// }

func reimplInvocation(u *unstructured.Unstructured) (slsa.ProvenanceInvocation, error) {
	i := slsa.ProvenanceInvocation{}
	// 1. config source
	s, found, err := unstructured.NestedMap(u.UnstructuredContent(), "status", "provenance", "configSource")
	if err != nil {
		return i, err
	}
	if found {
		if s["uri"] != nil {
			i.ConfigSource.URI = s["uri"].(string)
		}
		if s["digest"] != nil {
			digests := map[string]string{}
			if temp, ok := s["digest"].(map[string]interface{}); ok {
				for algo, v := range temp {
					if digest, ok := v.(string); ok {
						digests[algo] = digest
					}
				}
			}
			i.ConfigSource.Digest = digests
		}
		if s["entryPoint"] != nil {
			i.ConfigSource.EntryPoint = s["entryPoint"].(string)
		}
	}

	// 2. parameters
	p, err := reimplInvocationParams(u)
	if err != nil {
		return i, err
	}
	i.Parameters = p

	// 3. Environment
	e, err := reimplInvocationEnv(u)
	if err != nil {
		return i, err
	}
	i.Environment = e
	return i, nil
}

// // invocationEnv adds the tekton feature flags that were enabled
// // for the taskrun. In the future, we can populate versioning information
// // here as well.
// func invocationEnv(tro *objects.TaskRunObject) map[string]any {
// 	var iEnv map[string]any = make(map[string]any)
// 	if tro.Status.Provenance != nil && tro.Status.Provenance.FeatureFlags != nil {
// 		iEnv["tekton-pipelines-feature-flags"] = tro.Status.Provenance.FeatureFlags
// 	}
// 	return iEnv
// }

func reimplInvocationEnv(u *unstructured.Unstructured) (map[string]any, error) {
	iEnv := map[string]any{}
	flags, found, err := unstructured.NestedMap(u.UnstructuredContent(), "status", "provenance", "featureFlags")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	iEnv["tekton-pipelines-feature-flags"] = flags
	return iEnv, nil
}

// // invocationParams adds all fields from the task run object except
// // TaskRef or TaskSpec since they are in the ConfigSource or buildConfig.
// func invocationParams(tro *objects.TaskRunObject) map[string]any {
// 	var iParams map[string]any = make(map[string]any)
// 	skipFields := sets.NewString("TaskRef", "TaskSpec")
// 	v := reflect.ValueOf(tro.Spec)
// 	for i := 0; i < v.NumField(); i++ {
// 		fieldName := v.Type().Field(i).Name
// 		if !skipFields.Has(v.Type().Field(i).Name) {
// 			iParams[fieldName] = v.Field(i).Interface()
// 		}
// 	}
// 	return iParams
// }

func reimplInvocationParams(u *unstructured.Unstructured) (map[string]any, error) {
	trSpec, found, err := unstructured.NestedMap(u.UnstructuredContent(), "spec")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	delete(trSpec, "taskSpec")
	delete(trSpec, "taskRef")
	return trSpec, nil
}

// Metadata adds taskrun's start time, completion time and reproducibility labels
// to the metadata section of the generated provenance.
func reimplMetadata(u *unstructured.Unstructured) (*slsa.ProvenanceMetadata, error) {
	m := &slsa.ProvenanceMetadata{}
	startTime, found, err := unstructured.NestedFieldCopy(u.UnstructuredContent(), "status", "startTime")
	if err != nil {
		return nil, err
	}
	if found {
		start, ok := startTime.(*time.Time)
		if ok {
			m.BuildStartedOn = start
		}
	}
	completionTime, found, err := unstructured.NestedFieldCopy(u.UnstructuredContent(), "status", "completionTime")
	if err != nil {
		return nil, err
	}
	if found {
		complete, ok := completionTime.(*time.Time)
		if ok {
			m.BuildFinishedOn = complete
		}
	}

	for label, value := range u.GetLabels() {
		if label == "chains.tekton.dev/reproducible" && value == "true" {
			m.Reproducible = true
		}
	}
	return m, nil
}
