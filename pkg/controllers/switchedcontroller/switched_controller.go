package switchedcontroller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type ControllerWithSwitch struct {
	delegateName       string
	delegateFactoryFn  DelegateFactoryFunc
	delegateController factory.Controller

	switchConditionFn   DelegateSwitchCondition
	switchContext       context.Context
	switchContextCancel context.CancelFunc

	mutex sync.Mutex
}

// DelegateSwitchCondition defines a condition function that controls when the delegate
// controller must be switched on or off.
type DelegateSwitchCondition func() (bool, error)

// DelegateFactoryFunc returns a controller factory that can be used to create an instance
// of the delegate controller. The SwitchedController's context is passed to the function
// so that it may be used to start any informers that also depend on the DelegateSwitchCondition.
// This context is cancelled when DelegateSwitchCondition returns (false, nil).
type DelegateFactoryFunc func(context.Context) *factory.Factory

// NewControllerWithSwitch creates an instance of a switched controller. The switched controller is
// defined by the following:
// - delegateFactoryFn: a function that is invoked when a new instance of the delegate controller must be created
// - switchConditionFn: a function that is invoked on every switched controller sync to determine whether it needs to switch on/off the delegate controller
// - informers: any informers that must be tracked and are required by the switch condition
func NewControllerWithSwitch(
	operatorClient v1helpers.OperatorClient,
	delegateName string,
	delegateFactoryFn DelegateFactoryFunc,
	switchConditionFn DelegateSwitchCondition,
	informers []factory.Informer,
	resyncInterval time.Duration,
	eventRecorder events.Recorder,
) factory.Controller {

	c := &ControllerWithSwitch{
		delegateName:      delegateName,
		delegateFactoryFn: delegateFactoryFn,
		switchConditionFn: switchConditionFn,
	}

	return factory.New().
		WithSync(c.sync).
		WithSyncDegradedOnError(operatorClient).
		WithInformers(informers...).
		ResyncEvery(resyncInterval).
		ToController(delegateName+"_SwitchedController", eventRecorder)
}

func (c *ControllerWithSwitch) runDelegate(ctx context.Context, syncCtx factory.SyncContext) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.delegateController == nil {
		klog.Infof("[liouk] will create a new controller instance")
		c.delegateController = c.delegateFactoryFn(ctx).ToController(c.delegateName, syncCtx.Recorder())
	}
	go c.delegateController.Run(ctx, 1)
	klog.Infof("[liouk] controller go!")
}

func (c *ControllerWithSwitch) stopDelegate() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.switchContextCancel != nil {
		klog.Infof("[liouk] cancelling context")
		c.switchContextCancel()
	}

	klog.Infof("[liouk] resetting vars")
	c.switchContext = nil
	c.delegateController = nil
}

func (c *ControllerWithSwitch) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	if c.delegateFactoryFn == nil {
		return fmt.Errorf("no delegate factory function defined")
	}

	if c.switchConditionFn == nil {
		klog.Infof("no switch condition defined; controller '%s' will never be stopped", c.delegateName)
		c.runDelegate(ctx, syncCtx)
		return nil
	}

	switchOn, err := c.switchConditionFn()
	if err != nil {
		return fmt.Errorf("could not determine switch condition: %v", err)
	}
	// klog.Infof("[liouk] switchCondition: %t", switchOn)

	switch {
	case !switchOn && c.switchContext == nil:
		// we haven't been asked to start yet
		klog.Infof("[liouk] not asked to start yet")

	case switchOn && c.switchContext == nil:
		klog.Infof("[liouk] must start")
		c.switchContext, c.switchContextCancel = context.WithCancel(ctx)
		c.runDelegate(c.switchContext, syncCtx)

	case switchOn && c.switchContext != nil && c.switchContext.Err() == nil:
		// context alive, delegate running
		// klog.Infof("[liouk] context alive, delegate running")

	case !switchOn && c.switchContext != nil && c.switchContext.Err() == nil:
		klog.Infof("[liouk] must stop")
		c.stopDelegate()

	default:
		return fmt.Errorf("this should never happen; switchOn = %v; switchContext error = %v", switchOn, c.switchContext.Err())
	}

	return nil
}
