// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"errors"
	"io"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var initErr error

func init() {
	var d syscall.WSAData
	e := syscall.WSAStartup(uint32(0x202), &d)
	if e != nil {
		initErr = os.NewSyscallError("WSAStartup", e)
	}
}

func closesocket(s syscall.Handle) error {
	return syscall.Closesocket(s)
}

// Interface for all io operations.
type anOpIface interface {
	Op() *anOp
	Name() string
	Submit() error
}

// IO completion result parameters.
type ioResult struct {
	qty uint32
	err error
}

// anOp implements functionality common to all io operations.
type anOp struct {
	// Used by IOCP interface, it must be first field
	// of the struct, as our code rely on it.
	o syscall.Overlapped

	resultc chan ioResult
	errnoc  chan error
	fd      *netFD
}

func (o *anOp) Init(fd *netFD, mode int) {
	o.fd = fd
	var i int
	if mode == 'r' {
		i = 0
	} else {
		i = 1
	}
	if fd.resultc[i] == nil {
		fd.resultc[i] = make(chan ioResult, 1)
	}
	o.resultc = fd.resultc[i]
	if fd.errnoc[i] == nil {
		fd.errnoc[i] = make(chan error)
	}
	o.errnoc = fd.errnoc[i]
}

func (o *anOp) Op() *anOp {
	return o
}

// bufOp is used by io operations that read / write
// data from / to client buffer.
type bufOp struct {
	anOp
	buf syscall.WSABuf
}

func (o *bufOp) Init(fd *netFD, buf []byte, mode int) {
	o.anOp.Init(fd, mode)
	o.buf.Len = uint32(len(buf))
	if len(buf) == 0 {
		o.buf.Buf = nil
	} else {
		o.buf.Buf = (*byte)(unsafe.Pointer(&buf[0]))
	}
}

// resultSrv will retrieve all io completion results from
// iocp and send them to the correspondent waiting client
// goroutine via channel supplied in the request.
type resultSrv struct {
	iocp syscall.Handle
}

func (s *resultSrv) Run() {
	var o *syscall.Overlapped
	var key uint32
	var r ioResult
	for {
		r.err = syscall.GetQueuedCompletionStatus(s.iocp, &(r.qty), &key, &o, syscall.INFINITE)
		switch {
		case r.err == nil:
			// Dequeued successfully completed io packet.
		case r.err == syscall.Errno(syscall.WAIT_TIMEOUT) && o == nil:
			// Wait has timed out (should not happen now, but might be used in the future).
			panic("GetQueuedCompletionStatus timed out")
		case o == nil:
			// Failed to dequeue anything -> report the error.
			panic("GetQueuedCompletionStatus failed " + r.err.Error())
		default:
			// Dequeued failed io packet.
		}
		(*anOp)(unsafe.Pointer(o)).resultc <- r
	}
}

// ioSrv executes net io requests.
type ioSrv struct {
	submchan chan anOpIface // submit io requests
	canchan  chan anOpIface // cancel io requests
}

// ProcessRemoteIO will execute submit io requests on behalf
// of other goroutines, all on a single os thread, so it can
// cancel them later. Results of all operations will be sent
// back to their requesters via channel supplied in request.
func (s *ioSrv) ProcessRemoteIO() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for {
		select {
		case o := <-s.submchan:
			o.Op().errnoc <- o.Submit()
		case o := <-s.canchan:
			o.Op().errnoc <- syscall.CancelIo(syscall.Handle(o.Op().fd.sysfd))
		}
	}
}

// ExecIO executes a single io operation. It either executes it
// inline, or, if a deadline is employed, passes the request onto
// a special goroutine and waits for completion or cancels request.
// deadline is unix nanos.
func (s *ioSrv) ExecIO(oi anOpIface, deadline int64) (int, error) {
	var err error
	o := oi.Op()
	if deadline != 0 {
		// Send request to a special dedicated thread,
		// so it can stop the io with CancelIO later.
		s.submchan <- oi
		err = <-o.errnoc
	} else {
		err = oi.Submit()
	}
	switch err {
	case nil:
		// IO completed immediately, but we need to get our completion message anyway.
	case syscall.ERROR_IO_PENDING:
		// IO started, and we have to wait for its completion.
		err = nil
	default:
		return 0, &OpError{oi.Name(), o.fd.net, o.fd.laddr, err}
	}
	// Wait for our request to complete.
	var r ioResult
	if deadline != 0 {
		dt := deadline - time.Now().UnixNano()
		if dt < 1 {
			dt = 1
		}
		timer := time.NewTimer(time.Duration(dt) * time.Nanosecond)
		defer timer.Stop()
		select {
		case r = <-o.resultc:
		case <-timer.C:
			s.canchan <- oi
			<-o.errnoc
			r = <-o.resultc
			if r.err == syscall.ERROR_OPERATION_ABORTED { // IO Canceled
				r.err = syscall.EWOULDBLOCK
			}
		}
	} else {
		r = <-o.resultc
	}
	if r.err != nil {
		err = &OpError{oi.Name(), o.fd.net, o.fd.laddr, r.err}
	}
	return int(r.qty), err
}

// Start helper goroutines.
var resultsrv *resultSrv
var iosrv *ioSrv
var onceStartServer sync.Once

func startServer() {
	resultsrv = new(resultSrv)
	var err error
	resultsrv.iocp, err = syscall.CreateIoCompletionPort(syscall.InvalidHandle, 0, 0, 1)
	if err != nil {
		panic("CreateIoCompletionPort: " + err.Error())
	}
	go resultsrv.Run()

	iosrv = new(ioSrv)
	iosrv.submchan = make(chan anOpIface)
	iosrv.canchan = make(chan anOpIface)
	go iosrv.ProcessRemoteIO()
}

// Network file descriptor.
type netFD struct {
	// locking/lifetime of sysfd
	sysmu   sync.Mutex
	sysref  int
	closing bool

	// immutable until Close
	sysfd       syscall.Handle
	family      int
	sotype      int
	isConnected bool
	net         string
	laddr       Addr
	raddr       Addr
	resultc     [2]chan ioResult // read/write completion results
	errnoc      [2]chan error    // read/write submit or cancel operation errors

	// owned by client
	rdeadline int64
	rio       sync.Mutex
	wdeadline int64
	wio       sync.Mutex
}

func allocFD(fd syscall.Handle, family, sotype int, net string) *netFD {
	netfd := &netFD{
		sysfd:  fd,
		family: family,
		sotype: sotype,
		net:    net,
	}
	runtime.SetFinalizer(netfd, (*netFD).Close)
	return netfd
}

func newFD(fd syscall.Handle, family, proto int, net string) (*netFD, error) {
	if initErr != nil {
		return nil, initErr
	}
	onceStartServer.Do(startServer)
	// Associate our socket with resultsrv.iocp.
	if _, err := syscall.CreateIoCompletionPort(syscall.Handle(fd), resultsrv.iocp, 0, 0); err != nil {
		return nil, err
	}
	return allocFD(fd, family, proto, net), nil
}

func (fd *netFD) setAddr(laddr, raddr Addr) {
	fd.laddr = laddr
	fd.raddr = raddr
}

func (fd *netFD) connect(ra syscall.Sockaddr) error {
	return syscall.Connect(fd.sysfd, ra)
}

var errClosing = errors.New("use of closed network connection")

// Add a reference to this fd.
// If closing==true, mark the fd as closing.
// Returns an error if the fd cannot be used.
func (fd *netFD) incref(closing bool) error {
	if fd == nil {
		return errClosing
	}
	fd.sysmu.Lock()
	if fd.closing {
		fd.sysmu.Unlock()
		return errClosing
	}
	fd.sysref++
	if closing {
		fd.closing = true
	}
	closing = fd.closing
	fd.sysmu.Unlock()
	return nil
}

// Remove a reference to this FD and close if we've been asked to do so (and
// there are no references left.
func (fd *netFD) decref() {
	fd.sysmu.Lock()
	fd.sysref--
	// NOTE(rsc): On Unix we check fd.sysref == 0 here before closing,
	// but on Windows we have no way to wake up the blocked I/O other
	// than closing the socket (or calling Shutdown, which breaks other
	// programs that might have a reference to the socket).  So there is
	// a small race here that we might close fd.sysfd and then some other
	// goroutine might start a read of fd.sysfd (having read it before we
	// write InvalidHandle to it), which might refer to some other file
	// if the specific handle value gets reused.  I think handle values on
	// Windows are not reused as aggressively as file descriptors on Unix,
	// so this might be tolerable.
	if fd.closing && fd.sysfd != syscall.InvalidHandle {
		// In case the user has set linger, switch to blocking mode so
		// the close blocks.  As long as this doesn't happen often, we
		// can handle the extra OS processes.  Otherwise we'll need to
		// use the resultsrv for Close too.  Sigh.
		syscall.SetNonblock(fd.sysfd, false)
		closesocket(fd.sysfd)
		fd.sysfd = syscall.InvalidHandle
		// no need for a finalizer anymore
		runtime.SetFinalizer(fd, nil)
	}
	fd.sysmu.Unlock()
}

func (fd *netFD) Close() error {
	if err := fd.incref(true); err != nil {
		return err
	}
	fd.decref()
	return nil
}

func (fd *netFD) shutdown(how int) error {
	if fd == nil || fd.sysfd == syscall.InvalidHandle {
		return syscall.EINVAL
	}
	err := syscall.Shutdown(fd.sysfd, how)
	if err != nil {
		return &OpError{"shutdown", fd.net, fd.laddr, err}
	}
	return nil
}

func (fd *netFD) CloseRead() error {
	return fd.shutdown(syscall.SHUT_RD)
}

func (fd *netFD) CloseWrite() error {
	return fd.shutdown(syscall.SHUT_WR)
}

// Read from network.

type readOp struct {
	bufOp
}

func (o *readOp) Submit() error {
	var d, f uint32
	return syscall.WSARecv(syscall.Handle(o.fd.sysfd), &o.buf, 1, &d, &f, &o.o, nil)
}

func (o *readOp) Name() string {
	return "WSARecv"
}

func (fd *netFD) Read(buf []byte) (int, error) {
	if fd == nil {
		return 0, syscall.EINVAL
	}
	fd.rio.Lock()
	defer fd.rio.Unlock()
	if err := fd.incref(false); err != nil {
		return 0, err
	}
	defer fd.decref()
	if fd.sysfd == syscall.InvalidHandle {
		return 0, syscall.EINVAL
	}
	var o readOp
	o.Init(fd, buf, 'r')
	n, err := iosrv.ExecIO(&o, fd.rdeadline)
	if err == nil && n == 0 {
		err = io.EOF
	}
	return n, err
}

// ReadFrom from network.

type readFromOp struct {
	bufOp
	rsa  syscall.RawSockaddrAny
	rsan int32
}

func (o *readFromOp) Submit() error {
	var d, f uint32
	return syscall.WSARecvFrom(o.fd.sysfd, &o.buf, 1, &d, &f, &o.rsa, &o.rsan, &o.o, nil)
}

func (o *readFromOp) Name() string {
	return "WSARecvFrom"
}

func (fd *netFD) ReadFrom(buf []byte) (n int, sa syscall.Sockaddr, err error) {
	if fd == nil {
		return 0, nil, syscall.EINVAL
	}
	if len(buf) == 0 {
		return 0, nil, nil
	}
	fd.rio.Lock()
	defer fd.rio.Unlock()
	if err := fd.incref(false); err != nil {
		return 0, nil, err
	}
	defer fd.decref()
	var o readFromOp
	o.Init(fd, buf, 'r')
	o.rsan = int32(unsafe.Sizeof(o.rsa))
	n, err = iosrv.ExecIO(&o, fd.rdeadline)
	if err != nil {
		return 0, nil, err
	}
	sa, _ = o.rsa.Sockaddr()
	return
}

// Write to network.

type writeOp struct {
	bufOp
}

func (o *writeOp) Submit() error {
	var d uint32
	return syscall.WSASend(o.fd.sysfd, &o.buf, 1, &d, 0, &o.o, nil)
}

func (o *writeOp) Name() string {
	return "WSASend"
}

func (fd *netFD) Write(buf []byte) (int, error) {
	if fd == nil {
		return 0, syscall.EINVAL
	}
	fd.wio.Lock()
	defer fd.wio.Unlock()
	if err := fd.incref(false); err != nil {
		return 0, err
	}
	defer fd.decref()
	var o writeOp
	o.Init(fd, buf, 'w')
	return iosrv.ExecIO(&o, fd.wdeadline)
}

// WriteTo to network.

type writeToOp struct {
	bufOp
	sa syscall.Sockaddr
}

func (o *writeToOp) Submit() error {
	var d uint32
	return syscall.WSASendto(o.fd.sysfd, &o.buf, 1, &d, 0, o.sa, &o.o, nil)
}

func (o *writeToOp) Name() string {
	return "WSASendto"
}

func (fd *netFD) WriteTo(buf []byte, sa syscall.Sockaddr) (int, error) {
	if fd == nil {
		return 0, syscall.EINVAL
	}
	if len(buf) == 0 {
		return 0, nil
	}
	fd.wio.Lock()
	defer fd.wio.Unlock()
	if err := fd.incref(false); err != nil {
		return 0, err
	}
	defer fd.decref()
	if fd.sysfd == syscall.InvalidHandle {
		return 0, syscall.EINVAL
	}
	var o writeToOp
	o.Init(fd, buf, 'w')
	o.sa = sa
	return iosrv.ExecIO(&o, fd.wdeadline)
}

// Accept new network connections.

type acceptOp struct {
	anOp
	newsock syscall.Handle
	attrs   [2]syscall.RawSockaddrAny // space for local and remote address only
}

func (o *acceptOp) Submit() error {
	var d uint32
	l := uint32(unsafe.Sizeof(o.attrs[0]))
	return syscall.AcceptEx(o.fd.sysfd, o.newsock,
		(*byte)(unsafe.Pointer(&o.attrs[0])), 0, l, l, &d, &o.o)
}

func (o *acceptOp) Name() string {
	return "AcceptEx"
}

func (fd *netFD) accept(toAddr func(syscall.Sockaddr) Addr) (*netFD, error) {
	if err := fd.incref(false); err != nil {
		return nil, err
	}
	defer fd.decref()

	// Get new socket.
	// See ../syscall/exec_unix.go for description of ForkLock.
	syscall.ForkLock.RLock()
	s, err := syscall.Socket(fd.family, fd.sotype, 0)
	if err != nil {
		syscall.ForkLock.RUnlock()
		return nil, err
	}
	syscall.CloseOnExec(s)
	syscall.ForkLock.RUnlock()

	// Associate our new socket with IOCP.
	onceStartServer.Do(startServer)
	if _, err := syscall.CreateIoCompletionPort(s, resultsrv.iocp, 0, 0); err != nil {
		return nil, &OpError{"CreateIoCompletionPort", fd.net, fd.laddr, err}
	}

	// Submit accept request.
	var o acceptOp
	o.Init(fd, 'r')
	o.newsock = s
	_, err = iosrv.ExecIO(&o, fd.rdeadline)
	if err != nil {
		closesocket(s)
		return nil, err
	}

	// Inherit properties of the listening socket.
	err = syscall.Setsockopt(s, syscall.SOL_SOCKET, syscall.SO_UPDATE_ACCEPT_CONTEXT, (*byte)(unsafe.Pointer(&fd.sysfd)), int32(unsafe.Sizeof(fd.sysfd)))
	if err != nil {
		closesocket(s)
		return nil, err
	}

	// Get local and peer addr out of AcceptEx buffer.
	var lrsa, rrsa *syscall.RawSockaddrAny
	var llen, rlen int32
	l := uint32(unsafe.Sizeof(*lrsa))
	syscall.GetAcceptExSockaddrs((*byte)(unsafe.Pointer(&o.attrs[0])),
		0, l, l, &lrsa, &llen, &rrsa, &rlen)
	lsa, _ := lrsa.Sockaddr()
	rsa, _ := rrsa.Sockaddr()

	netfd := allocFD(s, fd.family, fd.sotype, fd.net)
	netfd.setAddr(toAddr(lsa), toAddr(rsa))
	return netfd, nil
}

// Unimplemented functions.

func (fd *netFD) dup() (*os.File, error) {
	// TODO: Implement this
	return nil, os.NewSyscallError("dup", syscall.EWINDOWS)
}

var errNoSupport = errors.New("address family not supported")

func (fd *netFD) ReadMsg(p []byte, oob []byte) (n, oobn, flags int, sa syscall.Sockaddr, err error) {
	return 0, 0, 0, nil, errNoSupport
}

func (fd *netFD) WriteMsg(p []byte, oob []byte, sa syscall.Sockaddr) (n int, oobn int, err error) {
	return 0, 0, errNoSupport
}
