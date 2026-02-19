package safe_close

import "sync"

// SafeClose can achieve safe close where CloseWait returns only after
// all sub goroutines exited.
//
//  1. Main service goroutine starts and wait on ReceiveCloseSignal and call Done before returns.
//  2. Any service's sub goroutine should be started by Attach and wait on ReceiveCloseSignal.
//  3. If any fatal err occurs, any service goroutine can call SendCloseSignal to close the service.
//     Note that CloseWait cannot be called in the service, otherwise it will be deadlocked.
//  4. Any third party caller can call CloseWait to close the service.
type SafeClose struct {
	m           sync.Mutex
	wg          sync.WaitGroup
	closeSignal chan struct{}
	done        chan struct{}
	doneOnce    sync.Once
	closeErr    error
}

func NewSafeClose() *SafeClose {
	return &SafeClose{
		closeSignal: make(chan struct{}),
		done:        make(chan struct{}),
	}
}

// CloseWait sends a close signal to SafeClose and wait until it is closed.
// It is concurrent safe and can be called multiple times.
// CloseWait blocks until s.Done() is called and all Attach-ed goroutines is done.
func (s *SafeClose) CloseWait() {
	s.SendCloseSignal(nil)
	s.wg.Wait()
	<-s.done
}

// SendCloseSignal sends a close signal.
func (s *SafeClose) SendCloseSignal(err error) {
	s.m.Lock()
	defer s.m.Unlock()

	select {
	case <-s.closeSignal:
		return
	default:
		if err != nil {
			s.closeErr = err
		}
		close(s.closeSignal)
	}
}

// Err returns the first SendCloseSignal error.
func (s *SafeClose) Err() error {
	s.m.Lock()
	defer s.m.Unlock()
	return s.closeErr
}

func (s *SafeClose) ReceiveCloseSignal() <-chan struct{} {
	return s.closeSignal
}

// Attach add this goroutine to s.wg CloseWait.
// f must receive closeSignal and call done when it is done.
// If s was closed, f will not run.
func (s *SafeClose) Attach(f func(done func(), closeSignal <-chan struct{})) {
	s.m.Lock()
	select {
	case <-s.closeSignal:
		s.m.Unlock()
		return
	default:
		s.wg.Add(1)
	}
	s.m.Unlock()

	go func() {
		f(s.wg.Done, s.closeSignal)
	}()
}

// Done notifies CloseWait that is done.
// It is concurrent safe and can be called multiple times.
func (s *SafeClose) Done() {
	s.doneOnce.Do(func() {
		close(s.done)
	})
}
