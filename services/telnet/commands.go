package telnet

const (
	Binary                       byte = 0
	Echo                         byte = 1
	PrepareToReconnect           byte = 2
	SuppressGoAhead              byte = 3
	ApproximateMessageSize       byte = 4
	Status                       byte = 5
	TimingMark                   byte = 6
	RemoteControlledTransmission byte = 7
	NegotiateOutputLineWidth     byte = 8
	NegotiateOutputPageSize      byte = 9
	NegotiateCarriageReturn      byte = 10
	NegotiateHorizontalTabStop   byte = 11
	NegotiateHorizontalTab       byte = 12
	NegotiateFormfeed            byte = 13
	NegotiateVerticalTabStop     byte = 14
	NegotiateVerticalTab         byte = 15
	NegotiateLinefeed            byte = 16
	ExtendedASCII                byte = 17
	ForceLogout                  byte = 18
	ByteMacro                    byte = 19
	DataEntryTerminal            byte = 20
	Supdup                       byte = 21
	SupdupOutput                 byte = 22
	SendLocation                 byte = 23
	TerminalType                 byte = 24
	EndOfRecord                  byte = 25
	TacacsUserIdentification     byte = 26
	OutputMarking                byte = 27
	TerminalLocationNumber       byte = 28
	Regime3270                   byte = 29
	X3Pad                        byte = 30
	WindowSize                   byte = 31
	TerminalSpeed                byte = 32
	RemoteFlowControl            byte = 33
	Linemode                     byte = 34
	XDisplayLocation             byte = 35
	OldEnvironmentVariables      byte = 36
	Authentication               byte = 37
	Encryption                   byte = 38
	NewEnvironmentVariables      byte = 39

	// Interpret As Command code.  Value is 255 according to RFC 854. ***/
	IAC byte = 255
	// Don't use option code.  Value is 254 according to RFC 854. ***/
	Dont byte = 254
	// Request to use option code.  Value is 253 according to RFC 854. ***/
	Do byte = 253
	// Refuse to use option code.  Value is 252 according to RFC 854. ***/
	Wont byte = 252
	// Agree to use option code.  Value is 251 according to RFC 854. ***/
	Will byte = 251
	// Start subnegotiation code.  Value is 250 according to RFC 854. ***/
	SubNegotiationStart byte = 250
	// Go Ahead code.  Value is 249 according to RFC 854. ***/
	GoAhead byte = 249
	// Erase Line code.  Value is 248 according to RFC 854. ***/
	EraseLine byte = 248
	// Erase Character code.  Value is 247 according to RFC 854. ***/
	EraseCharacter byte = 247
	// Are You There code.  Value is 246 according to RFC 854. ***/
	AreYouThere byte = 246
	// Abort Output code.  Value is 245 according to RFC 854. ***/
	AbortOutput byte = 245
	// Interrupt Process code.  Value is 244 according to RFC 854. ***/
	InterruptProcess byte = 244
	// Break code.  Value is 243 according to RFC 854. ***/
	TelnetBreak byte = 243
	// Data mark code.  Value is 242 according to RFC 854. ***/
	DataMark byte = 242
	// No Operation code.  Value is 241 according to RFC 854. ***/
	Nop byte = 241
	// End subnegotiation code.  Value is 240 according to RFC 854. ***/
	SubNegotiationEnd byte = 240
	// End of record code.  Value is 239. ***/
	Eor byte = 239
	// Abort code.  Value is 238. ***/
	Abort byte = 238
	// Suspend process code.  Value is 237. ***/
	Suspend byte = 237
	// End of file code.  Value is 236. ***/
	EndOfFile byte = 236
	// Synchronize code.  Value is 242. ***/
	Synchronize byte = 242
)
