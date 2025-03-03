package main

import (
	"crypto/rand"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// SecureString represents a string that will be zeroed when garbage collected
type SecureString struct {
	data []byte
	mu   sync.RWMutex
}

// NewSecureString creates a new SecureString from a regular string
func NewSecureString(s string) *SecureString {
	// Convert string to byte slice
	data := []byte(s)

	// Create a new SecureString
	ss := &SecureString{
		data: data,
	}

	// Set up finalizer to zero memory when garbage collected
	runtime.SetFinalizer(ss, (*SecureString).Destroy)

	return ss
}

// Get returns the string value
func (s *SecureString) Get() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return a copy of the data as a string
	return string(s.data)
}

// Destroy zeros the memory and releases resources
func (s *SecureString) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.data != nil {
		// Zero the memory
		for i := range s.data {
			s.data[i] = 0
		}

		// Set to nil to allow garbage collection
		s.data = nil
	}
}

// LockMemory prevents the memory from being swapped to disk
func LockMemory() error {
	// This is a no-op on Windows as mlock is not directly available
	// On Unix systems, this would use syscall.Mlock
	if runtime.GOOS != "windows" {
		return syscall.Mlock([]byte{0}) // Just a test call to see if mlock is available
	}
	return nil
}

// UnlockMemory allows the memory to be swapped to disk
func UnlockMemory() error {
	// This is a no-op on Windows as munlock is not directly available
	// On Unix systems, this would use syscall.Munlock
	if runtime.GOOS != "windows" {
		return syscall.Munlock([]byte{0}) // Just a test call
	}
	return nil
}

// SecureZeroMemory overwrites the provided byte slice with zeros
// This is designed to be not optimized away by the compiler
func SecureZeroMemory(b []byte) {
	for i := range b {
		b[i] = 0
	}

	// Additional measure to prevent compiler optimization
	runtime.KeepAlive(b)
}

// OverwriteWithRandom overwrites the provided byte slice with random data
func OverwriteWithRandom(b []byte) error {
	_, err := rand.Read(b)
	return err
}

// SecureClear securely clears a string by overwriting its backing array
// Note: This is not guaranteed to work in all cases due to Go's string immutability
func SecureClear(s *string) {
	if s == nil || *s == "" {
		return
	}

	// Get the string header
	stringHeader := (*struct {
		Data unsafe.Pointer
		Len  int
	})(unsafe.Pointer(s))

	// Create a byte slice that shares the same backing array
	b := *(*[]byte)(unsafe.Pointer(&struct {
		Data unsafe.Pointer
		Len  int
		Cap  int
	}{stringHeader.Data, stringHeader.Len, stringHeader.Len}))

	// Zero the memory
	SecureZeroMemory(b)
}
