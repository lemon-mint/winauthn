package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	WebAuthN = syscall.NewLazyDLL("webauthn.dll")

	WebAuthNGetApiVersionNumber                           = WebAuthN.NewProc("WebAuthNGetApiVersionNumber")
	WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable = WebAuthN.NewProc("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable")
	WebAuthNAuthenticatorMakeCredential                   = WebAuthN.NewProc("WebAuthNAuthenticatorMakeCredential")

	WinUser                = syscall.NewLazyDLL("user32.dll")
	WinUserGetActiveWindow = WinUser.NewProc("GetActiveWindow")

	WinKernel                 = syscall.NewLazyDLL("kernel32.dll")
	WinKernelGetConsoleWindow = WinKernel.NewProc("GetConsoleWindow")
)

type PWSTR = *uint16

//go:repr C
type WEBAUTHN_RP_ENTITY_INFORMATION struct {
	DwVersion uint32
	PwszId    PWSTR
	PwszName  PWSTR
	PwszIcon  PWSTR
}

//go:repr C
type WEBAUTHN_USER_ENTITY_INFORMATION struct {
	DwVersion       uint32
	CbId            uint32
	PbId            *byte
	PwszName        PWSTR
	PwszIcon        PWSTR
	PwszDisplayName PWSTR
}

//go:repr C
type WEBAUTHN_COSE_CREDENTIAL_PARAMETER struct {
	DwVersion          uint32
	PwszCredentialType PWSTR
	LAlg               int32
}

//go:repr C
type WEBAUTHN_COSE_CREDENTIAL_PARAMETERS struct {
	CCredentialParameters uint32
	PCredentialParameters *WEBAUTHN_COSE_CREDENTIAL_PARAMETER
}

//go:repr C
type WEBAUTHN_CLIENT_DATA struct {
	DwVersion        uint32
	CbClientDataJSON uint32
	PbClientDataJSON *byte
	PwszHashAlgId    PWSTR
}

//go:repr C
type WEBAUTHN_CREDENTIAL struct {
	DwVersion          uint32
	CbId               uint32
	PbId               *byte
	PwszCredentialType PWSTR
}

//go:repr C
type WEBAUTHN_CREDENTIALS struct {
	CCredentials uint32
	PCredentials *WEBAUTHN_CREDENTIAL
}

//go:repr C
type WEBAUTHN_EXTENSION struct {
	PwszExtensionIdentifier PWSTR
	CbExtension             uint32
	PvExtension             uintptr
}

//go:repr C
type WEBAUTHN_EXTENSIONS struct {
	CExtensions uint32
	PExtensions *WEBAUTHN_EXTENSION
}

//go:repr C
type WEBAUTHN_CREDENTIAL_EX struct {
	DwVersion          uint32
	CbId               uint32
	PbId               *byte
	PwszCredentialType PWSTR
	DwTransports       uint32
}

//go:repr C
type WEBAUTHN_CREDENTIAL_LIST struct {
	CCredentials  uint32
	PPCredentials **WEBAUTHN_CREDENTIAL_EX
}

//go:repr C
type WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS struct {
	DwVersion                         uint32
	DwTimeoutMilliseconds             uint32
	CredentialList                    WEBAUTHN_CREDENTIALS
	Extensions                        WEBAUTHN_EXTENSIONS
	DwAuthenticatorAttachment         uint32
	BRequireResidentKey               uint8
	DwUserVerificationRequirement     uint32
	DwAttestationConveyancePreference uint32
	DwFlags                           uint32
	PCancellationId                   *syscall.GUID
	PExcludeCredentialList            *WEBAUTHN_CREDENTIAL_LIST
	DwEnterpriseAttestation           uint32
	DwLargeBlobSupport                uint32
	BPreferResidentKey                uint8
}

//go:repr C
type WEBAUTHN_CREDENTIAL_ATTESTATION struct {
	DwVersion               uint32
	PwszFormatType          PWSTR
	CbAuthenticatorData     uint32
	PbAuthenticatorData     *byte
	CbAttestation           uint32
	PbAttestation           *byte
	DwAttestationDecodeType uint32
	PvAttestationDecode     uintptr
	CbAttestationObject     uint32
	PbAttestationObject     *byte
	CbCredentialId          uint32
	PbCredentialId          *byte
	Extensions              WEBAUTHN_EXTENSIONS
	DwUsedTransport         uint32
	BEpAtt                  uint8
	BLargeBlobSupported     uint8
	BResidentKey            uint8
}

func main() {

	ver, _, err := WebAuthNGetApiVersionNumber.Call()
	fmt.Println(ver, err)
	isUserVerifyingPlatformAuthenticatorAvailable, _, err := WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.Call()
	fmt.Println(isUserVerifyingPlatformAuthenticatorAvailable, err)

	hWnd, _, err := WinKernelGetConsoleWindow.Call()
	fmt.Println(hWnd, err)

	var pRpInfo WEBAUTHN_RP_ENTITY_INFORMATION
	var pUserInfo WEBAUTHN_USER_ENTITY_INFORMATION
	var pPubKeyCredParams WEBAUTHN_COSE_CREDENTIAL_PARAMETERS
	var pWebAuthnClientData WEBAUTHN_CLIENT_DATA
	var pWebAuthnMakeCredentialOptions WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS
	var pWebAuthnCredentialAttestation WEBAUTHN_CREDENTIAL_ATTESTATION

	hresult, _, err := syscall.Syscall9(WebAuthNAuthenticatorMakeCredential.Addr(), 7,
		uintptr(hWnd),
		uintptr(unsafe.Pointer(&pRpInfo)),
		uintptr(unsafe.Pointer(&pUserInfo)),
		uintptr(unsafe.Pointer(&pPubKeyCredParams)),
		uintptr(unsafe.Pointer(&pWebAuthnClientData)),
		uintptr(unsafe.Pointer(&pWebAuthnMakeCredentialOptions)),
		uintptr(unsafe.Pointer(&pWebAuthnCredentialAttestation)),
		0,
		0)
	fmt.Println(hresult, err)
}
