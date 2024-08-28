//+build darwin, freebsd, openbsd, netbsd
package main

import "core:sys/posix"

wordexp :: posix.wordexp
wordexp_t :: posix.wordexp_t
wordfree :: posix.wordfree
