# DNS-Parser
DNS message parser
 * Parse DNS header and payload from a stream of hex bytes
 * 
 * Input: stream of bytes in hex
 * Output: DNS header, question and answer
 *
 * Expected input: 
 "\x6d\x7c \x81\x80 \x00\x01 \x00\x01 \x00\x00 \x00\x00 \x07\x65 \x78\x61" \
"\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00" \
"\x01\x00\x01\x00\x01\x2a\x67\x00\x04\ x5d\xb8\xd8\x22"
	
Expected ouput:

;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 28028

;; Flags: qr rd ra; QUERY: 1; ANSWER: 1; AUTHORITY: 0; ADDITIONAL: 0

;; QUESTION SECTION:
;; example.com.                 IN      A

;; ANSWER SECTION:
example.com.            76391   IN      A       93.184.216.34
