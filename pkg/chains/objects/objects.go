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

package objects

import (
	"fmt"

	// "github.com/tektoncd/pipeline/pkg/apis/pipeline/pod"
	// "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	// "github.com/tektoncd/pipeline/pkg/client/clientset/versioned"
	// "github.com/tektoncd/pipeline/pkg/apis/pipeline/pod"
	// "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	// "github.com/tektoncd/pipeline/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var TaskrunResource = schema.GroupVersionResource{Group: "tekton.dev", Version: "v1beta1", Resource: "taskruns"}

// Label added to TaskRuns identifying the associated pipeline Task
const PipelineTaskLabel = "tekton.dev/pipelineTask"

// Object is used as a base object of all Kubernetes objects
// ref: https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.9.4/pkg/client#Object
type Object interface {
	// Metadata associated to all Kubernetes objects
	metav1.Object
	// Runtime identifying data
	runtime.Object
}

// we need to define our result/param type in Chains in order to handle the results parsed from raw json in a more efficient way.
// // Result is a generic key value store containing the results
// // of Tekton operations. (eg. PipelineRun and TaskRun results)
//
//	type Result struct {
//		Name  string
//		Type  v1beta1.ResultsType
//		Value v1beta1.ArrayOrString
//	}
type Result struct {
	Name  string   `json:"name"`
	Value DataType `json:"value"`
}

type DataType struct {
	Type      string            `json:"type"`
	StringVal string            `json:"stringVal"`
	ArrayVal  []string          `json:"arrayVal"`
	ObjectVal map[string]string `json:"objectVal"`
}

// TODO 3: refactor TektonObject to be based on unstructured object and have some common operations to the objects
// (i.e. status.results, status.spec, status.starttime completeiontime etc.)

// Tekton object is an extended Kubernetes object with operations specific
// to Tekton objects.
type TektonObject interface {
	Object
	GetGVK() string
	GetObject() interface{}
	// GetLatestAnnotations(ctx context.Context, clientSet versioned.Interface) (map[string]string, error)
	// Patch(ctx context.Context, clientSet versioned.Interface, patchBytes []byte) error
	// GetResults() []Result
	// GetServiceAccountName() string
	// GetPullSecrets() []string
	// IsDone() bool
	// IsSuccessful() bool
}

// func NewTektonObject(i interface{}) (TektonObject, error) {
// 	switch o := i.(type) {
// 	case *v1beta1.PipelineRun:
// 		return NewPipelineRunObject(o), nil
// 	case *v1beta1.TaskRun:
// 		return NewTaskRunObject(o), nil
// 	default:
// 		return nil, errors.New("unrecognized type when attempting to create tekton object")
// 	}
// }

// TaskRunObject extends v1beta1.TaskRun with additional functions.
type TaskRunObject struct {
	*unstructured.Unstructured
}

var _ TektonObject = &TaskRunObject{}

// Get the TaskRun GroupVersionKind
func (tro *TaskRunObject) GetGVK() string {
	return fmt.Sprintf("%s/%s", tro.GroupVersionKind().GroupVersion().String(), tro.GroupVersionKind().GroupKind().Kind)
}

// // Get the latest annotations on the TaskRun
// func (tro *TaskRunObject) GetLatestAnnotations(ctx context.Context, clientSet versioned.Interface) (map[string]string, error) {
// 	tr, err := clientSet.TektonV1beta1().TaskRuns(tro.Namespace).Get(ctx, tro.Name, v1.GetOptions{})
// 	return tr.Annotations, err
// }

// Get the base TaskRun object
func (tro *TaskRunObject) GetObject() interface{} {
	return tro.Unstructured
}

// // Patch the original TaskRun object
// func (tro *TaskRunObject) Patch(ctx context.Context, clientSet versioned.Interface, patchBytes []byte) error {
// 	_, err := clientSet.TektonV1beta1().TaskRuns(tro.Namespace).Patch(
// 		ctx, tro.Name, types.MergePatchType, patchBytes, v1.PatchOptions{})
// 	return err
// }

// // Get the TaskRun results
// func (tro *TaskRunObject) GetResults() []Result {
// 	res := []Result{}
// 	for _, key := range tro.Status.TaskRunResults {
// 		res = append(res, Result{
// 			Name: key.Name,
// 			Value: DataType{
// 				Type:      string(key.Type),
// 				StringVal: key.Value.StringVal,
// 				ArrayVal:  key.Value.ArrayVal,
// 				ObjectVal: key.Value.ObjectVal,
// 			},
// 		})
// 	}
// 	return res
// }

// // Get the ServiceAccount declared in the TaskRun
// func (tro *TaskRunObject) GetServiceAccountName() string {
// 	return tro.Spec.ServiceAccountName
// }

// // Get the imgPullSecrets from the pod template
// func (tro *TaskRunObject) GetPullSecrets() []string {
// 	return getPodPullSecrets(tro.Spec.PodTemplate)
// }

// // PipelineRunObject extends v1beta1.PipelineRun with additional functions.
// type PipelineRunObject struct {
// 	// The base PipelineRun
// 	*v1beta1.PipelineRun
// 	// taskRuns that were apart of this PipelineRun
// 	taskRuns []*v1beta1.TaskRun
// }

// var _ TektonObject = &PipelineRunObject{}

// func NewPipelineRunObject(pr *v1beta1.PipelineRun) *PipelineRunObject {
// 	return &PipelineRunObject{
// 		PipelineRun: pr,
// 	}
// }

// // Get the PipelineRun GroupVersionKind
// func (pro *PipelineRunObject) GetGVK() string {
// 	return fmt.Sprintf("%s/%s", pro.GetGroupVersionKind().GroupVersion().String(), pro.GetGroupVersionKind().Kind)
// }

// // Request the current annotations on the PipelineRun object
// func (pro *PipelineRunObject) GetLatestAnnotations(ctx context.Context, clientSet versioned.Interface) (map[string]string, error) {
// 	pr, err := clientSet.TektonV1beta1().PipelineRuns(pro.Namespace).Get(ctx, pro.Name, v1.GetOptions{})
// 	return pr.Annotations, err
// }

// // Get the base PipelineRun
// func (pro *PipelineRunObject) GetObject() interface{} {
// 	return pro.PipelineRun
// }

// // Patch the original PipelineRun object
// func (pro *PipelineRunObject) Patch(ctx context.Context, clientSet versioned.Interface, patchBytes []byte) error {
// 	_, err := clientSet.TektonV1beta1().PipelineRuns(pro.Namespace).Patch(
// 		ctx, pro.Name, types.MergePatchType, patchBytes, v1.PatchOptions{})
// 	return err
// }

// // Get the resolved Pipelinerun results
// func (pro *PipelineRunObject) GetResults() []Result {
// 	res := []Result{}
// 	for _, key := range pro.Status.PipelineResults {
// 		res = append(res, Result{
// 			Name: key.Name,
// 			Value: DataType{
// 				Type:      string(key.Value.Type),
// 				StringVal: key.Value.StringVal,
// 				ArrayVal:  key.Value.ArrayVal,
// 				ObjectVal: key.Value.ObjectVal,
// 			},
// 		})
// 	}
// 	return res
// }

// // Get the ServiceAccount declared in the PipelineRun
// func (pro *PipelineRunObject) GetServiceAccountName() string {
// 	return pro.Spec.ServiceAccountName
// }

// // Get the ServiceAccount declared in the PipelineRun
// func (pro *PipelineRunObject) IsSuccessful() bool {
// 	return pro.Status.GetCondition(apis.ConditionSucceeded).IsTrue()
// }

// // Append TaskRuns to this PipelineRun
// func (pro *PipelineRunObject) AppendTaskRun(tr *v1beta1.TaskRun) {
// 	pro.taskRuns = append(pro.taskRuns, tr)
// }

// // Get the associated TaskRun via the Task name
// func (pro *PipelineRunObject) GetTaskRunFromTask(taskName string) *v1beta1.TaskRun {
// 	for _, tr := range pro.taskRuns {
// 		val, ok := tr.Labels[PipelineTaskLabel]
// 		if ok && val == taskName {
// 			return tr
// 		}
// 	}
// 	return nil
// }

// // Get the imgPullSecrets from the pod template
// func (pro *PipelineRunObject) GetPullSecrets() []string {
// 	return getPodPullSecrets(pro.Spec.PodTemplate)
// }

// // Get the imgPullSecrets from a pod template, if they exist
// func getPodPullSecrets(podTemplate *pod.Template) []string {
// 	imgPullSecrets := []string{}
// 	if podTemplate != nil {
// 		for _, secret := range podTemplate.ImagePullSecrets {
// 			imgPullSecrets = append(imgPullSecrets, secret.Name)
// 		}
// 	}
// 	return imgPullSecrets
// }
