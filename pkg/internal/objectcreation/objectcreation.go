package objectcreation

import (
	"context"
	"fmt"

	"github.com/tektoncd/chains/pkg/chains/objects"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
)

func NewTaskRunObject(ctx context.Context, dc dynamic.Interface, tr *v1beta1.TaskRun) (*objects.TaskRunObject, error) {
	unstructuredTr, err := dc.Resource(objects.TaskrunResource).Namespace(tr.Namespace).Get(ctx, tr.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("not able to find the taskrun: %v", err)
	}
	return &objects.TaskRunObject{
		Unstructured: unstructuredTr,
	}, nil
}
