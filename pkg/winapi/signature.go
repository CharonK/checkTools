//go:build windows

package winapi

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	WTD_UI_NONE            = 2
	WTD_REVOKE_NONE        = 0
	WTD_STATEACTION_VERIFY = 1
	WTD_STATEACTION_CLOSE  = 2
	WTD_CHOICE_FILE        = 1

	ERROR_SUCCESS       = 0
	TRUST_E_NOSIGNATURE = 0x800B0100
	TRUST_E_BAD_DIGEST  = 0x80096010
)

type WINTRUST_FILE_INFO struct {
	CbStruct       uint32
	PcwszFilePath  *uint16
	HFile          windows.Handle
	PgKnownSubject *windows.GUID
}

type WINTRUST_DATA struct {
	CbStruct            uint32
	PPolicyCallbackData uintptr
	PSIPClientData      uintptr
	DwUIChoice          uint32
	FdwRevocationChecks uint32
	DwUnionChoice       uint32
	PFile               *WINTRUST_FILE_INFO
	DwStateAction       uint32
	HWVTStateData       windows.Handle
	PwszURLReference    *uint16
	DwProvFlags         uint32
	DwUIContext         uint32
}

var (
	wintrustDll        = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust = wintrustDll.NewProc("WinVerifyTrust")

	genericVerifyGUID = windows.GUID{
		Data1: 0xaac56b,
		Data2: 0xcd44,
		Data3: 0x11d0,
		Data4: [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee},
	}
)

// VerifyFileSignature 验证文件数字签名，返回状态：已签名(有效)/未签名/签名无效/无法验证
func VerifyFileSignature(filePath string) string {
	if filePath == "" {
		return "-"
	}

	pathPtr, err := windows.UTF16PtrFromString(filePath)
	if err != nil {
		return "无法验证"
	}

	fileInfo := &WINTRUST_FILE_INFO{
		CbStruct:      uint32(unsafe.Sizeof(WINTRUST_FILE_INFO{})),
		PcwszFilePath: pathPtr,
	}

	trustData := &WINTRUST_DATA{
		CbStruct:            uint32(unsafe.Sizeof(WINTRUST_DATA{})),
		DwUIChoice:          WTD_UI_NONE,
		FdwRevocationChecks: WTD_REVOKE_NONE,
		DwUnionChoice:       WTD_CHOICE_FILE,
		PFile:               fileInfo,
		DwStateAction:       WTD_STATEACTION_VERIFY,
	}

	ret, _, _ := procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&genericVerifyGUID)),
		uintptr(unsafe.Pointer(trustData)),
	)

	// 释放验证状态资源
	trustData.DwStateAction = WTD_STATEACTION_CLOSE
	_, _, _ = procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&genericVerifyGUID)),
		uintptr(unsafe.Pointer(trustData)),
	)

	switch uint32(ret) {
	case ERROR_SUCCESS:
		return "已签名(有效)"
	case TRUST_E_NOSIGNATURE:
		return "未签名"
	case TRUST_E_BAD_DIGEST:
		return "签名无效"
	default:
		return "验证失败"
	}
}