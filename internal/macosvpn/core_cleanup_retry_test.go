package macosvpn

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestCoreRetryCleanupRejectsLiveAndInvalidContext(t *testing.T) {
	a, _, v := coreBridgeFixture(t)
	session, err := a.Start(context.Background(), a.profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := awaitCoreResult(t, session.Ready()); err != nil {
		t.Fatal(err)
	}
	s := session.(*existingCoreSession)
	defer s.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []context.Context{nil, ctx, context.Background()} {
		if !isCoreCleanupError(s.RetryCleanup(input)) {
			t.Fatal("未拒绝无效上下文或活动会话重试")
		}
	}
	if s.ctx.Err() != nil || v.restores.Load() != 0 {
		t.Fatal("清理重试意外断开了活动会话")
	}
}

func TestCoreRetryCleanupCallerDeadlineRetainsWorker(t *testing.T) {
	a, _, v := coreBridgeFixture(t)
	a.stopTimeout = time.Second
	entered, release := make(chan struct{}), make(chan struct{})
	var attempts atomic.Int32
	v.restoreFn = func(context.Context) error {
		n := attempts.Add(1)
		if n == 1 {
			return errors.New("injected cleanup uncertainty")
		}
		if n == 2 {
			close(entered)
			<-release
		}
		return nil
	}
	session, err := a.Start(context.Background(), a.profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := awaitCoreResult(t, session.Ready()); err != nil {
		t.Fatal(err)
	}
	s := session.(*existingCoreSession)
	s.cancel()
	<-s.workerDone
	alreadyCanceled, cancelEarly := context.WithCancel(context.Background())
	cancelEarly()
	if !isCoreCleanupError(s.RetryCleanup(alreadyCanceled)) || attempts.Load() != 1 {
		t.Fatal("已取消重试启动了新的原生清理")
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- s.RetryCleanup(ctx) }()
	<-entered
	cancel()
	if !isCoreCleanupError(awaitCoreResult(t, result)) {
		t.Fatal("取消等待错误地确认清理完成")
	}
	// A second caller waits for the same native operation, not another release.
	short, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	if !isCoreCleanupError(s.RetryCleanup(short)) {
		t.Fatal("未完成的原生清理丢失隔离")
	}
	if attempts.Load() != 2 {
		t.Fatal("重复进入原生清理")
	}
	close(release)
	if err := s.RetryCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 2 {
		t.Fatal("未复用已完成的清理证据")
	}
	if err := s.RetryCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 2 {
		t.Fatal("成功后的重复验证再次执行清理")
	}
}
