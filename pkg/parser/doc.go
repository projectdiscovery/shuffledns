// Package parser is a package for parsing massdns output
// format. Massdns writes output in a dig style format
// containing complete information about the resolved names.
//
// Only a subset of information, more specifically Name and
// IP address is parsed from the output. It correctly handles
// CNAME record entries outputting the first name and the subsequent
// A records. NS records are ignored in the current implementation.
package parser
