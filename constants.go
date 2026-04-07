package wmi

const (
	comVersionMajor = 5
	comVersionMinor = 7
)

// WBEM timeout constants.
const (
	WBEMInfinite = 0xffffffff
	WBEMNoWait   = 0x0
)

// WBEM query flag constants.
const (
	WBEMFlagUseAmendedQualifiers = 0x00020000
	WBEMFlagReturnImmediately    = 0x00000010
	WBEMFlagDirectRead           = 0x00000200
	WBEMFlagPrototype            = 0x00000002
	WBEMFlagForwardOnly          = 0x00000020
	WBEMFlagSendStatus           = 0x00000080
)

const (
	wbemSNoError        = 0x00000000
	wbemSFalse          = 0x00000001
	wbemSTimedOut       = 0x00040004
	wbemSNewStyle       = 0x000400ff
	wbemSPartialResults = 0x00040010

	wbemEFailed                      = 0x80041001
	wbemENotFound                    = 0x80041002
	wbemEAccessDenied                = 0x80041003
	wbemEProviderFailure             = 0x80041004
	wbemETypeMismatch                = 0x80041005
	wbemEOutOfMemory                 = 0x80041006
	wbemEInvalidContext              = 0x80041007
	wbemEInvalidParameter            = 0x80041008
	wbemENotAvailable                = 0x80041009
	wbemECriticalError               = 0x8004100a
	wbemENotSupported                = 0x8004100c
	wbemEInvalidSuperclass           = 0x8004100d
	wbemEInvalidNamespace            = 0x8004100e
	wbemEInvalidObject               = 0x8004100f
	wbemEInvalidClass                = 0x80041010
	wbemEProviderNotFound            = 0x80041011
	wbemEInvalidProviderRegistration = 0x80041012
	wbemEProviderLoadFailure         = 0x80041013
	wbemEInitializationFailure       = 0x80041014
	wbemETransportFailure            = 0x80041015
	wbemEInvalidOperation            = 0x80041016
	wbemEInvalidQuery                = 0x80041017
	wbemEInvalidQueryType            = 0x80041018
	wbemEAlreadyExists               = 0x80041019
	wbemEUnexpected                  = 0x8004101d
	wbemEIncompleteClass             = 0x80041020
	wbemEProviderNotCapable          = 0x80041024
	wbemEClassHasChildren            = 0x80041025
	wbemEClassHasInstances           = 0x80041026
	wbemEIllegalNull                 = 0x80041028
	wbemEInvalidCimType              = 0x8004102d
	wbemEInvalidMethod               = 0x8004102e
	wbemEInvalidMethodParameters     = 0x8004102f
	wbemEInvalidProperty             = 0x80041031
	wbemECallCancelled               = 0x80041032
	wbemEShuttingDown                = 0x80041033
	wbemEInvalidObjectPath           = 0x8004103a
	wbemEOutOfDiskSpace              = 0x8004103b
	wbemEUnsupportedPutExtension     = 0x8004103d
	wbemEServerTooBusy               = 0x80041045
	wbemEMethodNotImplemented        = 0x80041055
	wbemEMethodDisabled              = 0x80041056
	wbemEUnparsableQuery             = 0x80041058
	wbemENotEventClass               = 0x80041059
	wbemEMissingGroupWithin          = 0x8004105a
	wbemEMissingAggregationList      = 0x8004105b
	wbemEPropertyNotAnObject         = 0x8004105c
	wbemEAggregatingByObject         = 0x8004105d
	wbemEBackupRestoreWinmgmtRunning = 0x80041060
	wbemEQueueOverflow               = 0x80041061
	wbemEPrivilegeNotHeld            = 0x80041062
	wbemEInvalidOperator             = 0x80041063
	wbemECannotBeAbstract            = 0x80041065
	wbemEAmendedObject               = 0x80041066
	wbemEQuotaViolation              = 0x8004106c
	wbemEVetoPut                     = 0x8004107a
	wbemEProviderSuspended           = 0x80041081
	wbemEEncryptedConnectionRequired = 0x80041087
	wbemEProviderTimedOut            = 0x80041088
	wbemENoKey                       = 0x80041089
	wbemEProviderDisabled            = 0x8004108a
	wbemERegistrationTooBroad        = 0x80042001
	wbemERegistrationTooPrecise      = 0x80042002
	wbemENotImpl                     = 0x80004001
)

var dictionaryReference = map[uint32]string{
	0:  "\"",
	1:  "key",
	2:  "NADA",
	3:  "read",
	4:  "write",
	5:  "volatile",
	6:  "provider",
	7:  "dynamic",
	8:  "cimwin32",
	9:  "DWORD",
	10: "CIMTYPE",
}

const (
	msrpcRequest   = 0x00
	msrpcResponse  = 0x02
	msrpcFault     = 0x03
	msrpcBind      = 0x0b
	msrpcBindAck   = 0x0c
	msrpcBindNak   = 0x0d
	msrpcAlterCtx  = 0x0e
	msrpcAlterCtxR = 0x0f
	msrpcAuth3     = 0x10
)

const (
	pfcFirstFrag  = 0x01
	pfcLastFrag   = 0x02
	pfcObjectUUID = 0x80
)

const (
	rpcCAuthNGSSNegotiate = 0x09
	rpcCAuthNWinNT        = 0x0a
)

const (
	rpcCAuthNLevelConnect      = 2
	rpcCAuthNLevelPktIntegrity = 5
	rpcCAuthNLevelPktPrivacy   = 6
)

const (
	rpcBindNakReasonNotSpecified               = 0
	rpcBindNakReasonTemporaryCongestion        = 1
	rpcBindNakReasonLocalLimitExceeded         = 2
	rpcBindNakReasonProtocolVersionUnsupported = 3
	rpcBindNakReasonAuthTypeUnsupported        = 4
	rpcBindNakReasonInvalidAuthInstance        = 5
)

const (
	rpcAccessDenied   = 0x00000005
	rpcAuthnLevelLow  = 0x000006d3
	rpcProtseqDenied  = 0x00000501
	rpcSecPkgError    = 0x00000721
	rpcSCannotSupport = 0x000006e4
	rpcSWrongAuth     = 0x1c01000b
	rpcNCaServerBusy  = 0x1c010014
)

const (
	ntlmSSPNegotiate56                      = 0x80000000
	ntlmSSPNegotiateKeyExch                 = 0x40000000
	ntlmSSPNegotiate128                     = 0x20000000
	ntlmSSPNegotiateVersion                 = 0x02000000
	ntlmSSPNegotiateTargetInfo              = 0x00800000
	ntlmSSPNegotiateExtendedSessionSecurity = 0x00080000
	ntlmSSPNegotiateAlwaysSign              = 0x00008000
	ntlmSSPNegotiateOEMWorkstationSupplied  = 0x00002000
	ntlmSSPNegotiateOEMDomainSupplied       = 0x00001000
	ntlmSSPNegotiateNTLM                    = 0x00000200
	ntlmSSPNegotiateSeal                    = 0x00000020
	ntlmSSPNegotiateSign                    = 0x00000010
	ntlmSSPRequestTarget                    = 0x00000004
	ntlmSSPNegotiateUnicode                 = 0x00000001
)

const (
	ntlmSSPAvEOL        = 0x00
	ntlmSSPAvHostname   = 0x01
	ntlmSSPAvTime       = 0x07
	ntlmSSPAvTargetName = 0x09
)

const (
	flagsObjrefStandard = 0x00000001
	flagsObjrefCustom   = 0x00000004
	flagsObjrefExtended = 0x00000008
)

const (
	cimArrayFlag     = 0x2000
	cimInheritedFlag = 0x4000

	cimTypeSInt8     = 16
	cimTypeUInt8     = 17
	cimTypeSInt16    = 2
	cimTypeUInt16    = 18
	cimTypeSInt32    = 3
	cimTypeUInt32    = 19
	cimTypeSInt64    = 20
	cimTypeUInt64    = 21
	cimTypeReal32    = 4
	cimTypeReal64    = 5
	cimTypeBoolean   = 11
	cimTypeString    = 8
	cimTypeDateTime  = 101
	cimTypeReference = 102
	cimTypeChar16    = 103
	cimTypeObject    = 13
)

var (
	clsidIWbemLevel1Login       = mustUUIDToBin("8BC3F05E-D86B-11D0-A075-00C04FB68820")
	clsidActivationPropertiesIn = mustUUIDToBin("00000338-0000-0000-C000-000000000046")
	clsidInstantiationInfo      = mustUUIDToBin("000001AB-0000-0000-C000-000000000046")
	clsidActivationContextInfo  = mustUUIDToBin("000001A5-0000-0000-C000-000000000046")
	clsidServerLocationInfo     = mustUUIDToBin("000001A4-0000-0000-C000-000000000046")
	clsidScmRequestInfo         = mustUUIDToBin("000001AA-0000-0000-C000-000000000046")

	iidIWbemLevel1Login         = mustUUIDVerToBin("F309AD18-D86A-11D0-A075-00C04FB68820", "0.0")
	iidIRemoteSCMActivator      = mustUUIDVerToBin("000001A0-0000-0000-C000-000000000046", "0.0")
	iidIActivationPropertiesIn  = mustUUIDVerToBin("000001A2-0000-0000-C000-000000000046", "0.0")
	iidIWbemFetchSmartEnumBin   = mustUUIDToBin("1C1C45EE-4395-11D2-B60B-00104B703EFD")
	ndrTransferSyntaxIdentifier = mustUUIDVerToBin("8A885D04-1CEB-11C9-9FE8-08002B104860", "2.0")
)
