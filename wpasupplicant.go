package wpasupplicant

import (
	"net"
)

type Cipher int

const (
	CIPHER_NONE Cipher = 1 << iota
	WEP40
	WEP104
	TKIP
	CCMP
	AES_128_CMAC
	GCMP
	SMS4
	GCMP_256
	CCMP_256
	_
	BIP_GMAC_128
	BIP_GMAC_256
	BIP_CMAC_256
	GTK_NOT_USED
)

type KeyMgmt int

const (
	IEEE8021X KeyMgmt = 1 << iota
	PSK
	KEY_MGMT_NONE
	IEEE8021X_NO_WPA
	WPA_NONE
	FT_IEEE8021X
	FT_PSK
	IEEE8021X_SHA256
	PSK_SHA256
	WPS
	SAE
	FT_SAE
	WAPI_PSK
	WAPI_CERT
	CCKM
	OSEN
	IEEE8021X_SUITE_B
	IEEE8021X_SUITE_B_192
)

type Algorithm int

type ScanResult interface {
	BSSID() net.HardwareAddr
	SSID() string
	Frequency() int
	RSSI() int
	Flags() []string
}

type scanResult struct {
	bssid     net.HardwareAddr
	ssid      string
	frequency int
	rssi      int
	flags     []string
}

func (r *scanResult) BSSID() net.HardwareAddr { return r.bssid }
func (r *scanResult) SSID() string            { return r.ssid }
func (r *scanResult) Frequency() int          { return r.frequency }
func (r *scanResult) RSSI() int               { return r.rssi }
func (r *scanResult) Flags() []string         { return r.flags }

type Conn interface {
	Ping() error

	ScanResults() ([]ScanResult, error)
}
