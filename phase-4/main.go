// This Code, Reads a Wireshark capture file (.pcap or .pcapng)
// parses the HTTP packets in it, and prints a one-line summary
// for each: source/destination IP:port, and either the request line or the
// response status code.
//
// How to run: read readme.md (Phase 4)

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	// *Open the file(.pcapng)*
	//if user dosent enter the file address (like: go run .), read the file
	// from this default address ("..\\captures\\Capture1_neverssl.pcapng") .
	// Else if user entered the file address (like: go run . D:\....\example.pcapng), use that file
	var filename string
	if len(os.Args) < 2 {
		filename = "..\\captures\\Capture1_neverssl.pcapng"
	} else {
		filename = os.Args[1]
	}
	f, err := os.Open(filename)

	// error check
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error opening capture file:", err)
		os.Exit(1)
	}

	defer f.Close()

	// Open the capture file and get its packet source & link-layer type (see the openCapture func that i made)
	source, linkType, err := openCapture(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading capture file:", err)
		os.Exit(1)
	}
	// Process each packet in the capture file
	for pkt := range gopacket.NewPacketSource(source, linkType).Packets() {
		printIfHTTP(pkt)
	}
}

// openCapture opens f as pcapng, falling back to classic pcap if that fails.
// Both formats are handled by pcapgo, part of gopacket
func openCapture(f *os.File) (gopacket.PacketDataSource, layers.LinkType, error) {
	// Try open the capture file in .pcapng format
	if r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions); err == nil {
		return r, r.LinkType(), nil
	}
	// Reset file position to the beginning, before trying another format
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, 0, err
	}
	// If .pcapng failed, Try open the capture file in .pcap format
	r, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, 0, fmt.Errorf("unrecognized capture format (tried .pcapng and .pcap): %w", err)
	}
	return r, r.LinkType(), nil
}

// printIfHTTP inspects one packet's TCP payload and, if it looks like an
// HTTP request or response, prints a one-line summary of it.
func printIfHTTP(pkt gopacket.Packet) {
	// Check IP & TCP layer
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	// Reject Another types
	if ipLayer == nil || tcpLayer == nil {
		return
	}
	// Access to their fields
	ip := ipLayer.(*layers.IPv4)
	tcp := tcpLayer.(*layers.TCP)
	//payload=0 means there is no data (TCP ACK, TCP SYN, TCP FIN,...) so we dont need it
	if len(tcp.Payload) == 0 {
		return
	}
	//Source and destination IP:Port
	src := fmt.Sprintf("%s:%d", ip.SrcIP, tcp.SrcPort)
	dst := fmt.Sprintf("%s:%d", ip.DstIP, tcp.DstPort)

	// Check be HTTP Request, and print it
	if req, ok := parseHTTPRequest(tcp.Payload); ok {
		fmt.Printf("[Request]  %-21s -> %-21s  %s %s\n", src, dst, req.Method, req.URL.Path)
		return
	}
	// Check be HTTP Response, and print it
	if status, ok := parseHTTPStatusCode(tcp.Payload); ok {
		fmt.Printf("[Response] %-21s -> %-21s  Status: %d\n", src, dst, status)
	}
}

var requestPrefixes = []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "}


// parseHTTPRequest returns the parsed request line if payload starts with a
// recognized HTTP method and is a well-formed request
func parseHTTPRequest(payload []byte) (*http.Request, bool) {
	// Initial assumption: it isnt request
	matches := false

	// Loop on methods
	for _, prefix := range requestPrefixes {
		// Find method (e.g: GET ....)
		if bytes.HasPrefix(payload, []byte(prefix)) {
			matches = true
			break
		}
	}

	// It hase not method
	if !matches {
		return nil, false
	}

	// Extract request's fields (e.g: req.method = GET)
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
	if err != nil {
		return nil, false
	}
	return req, true
}


// parseHTTPStatusCode returns the status code if payload starts with an
// HTTP status line and is a well-formed response (e.g: HTTP/1.1 200 OK)
func parseHTTPStatusCode(payload []byte) (int, bool) {
	// If it dosent start with HTTP/1.1 , its not a response
	if !bytes.HasPrefix(payload, []byte("HTTP/")) {
		return 0, false
	}

	// http.ReadResponse only needs the request's Method (to know whether a
	// HEAD response should have no body); we never read the body, so a
	// dummy GET request is enough here.
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(payload)), &http.Request{Method: "GET"})
	if err != nil {
		return 0, false
	}
	return resp.StatusCode, true
}
