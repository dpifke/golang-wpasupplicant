package wpasupplicant

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
)

type message struct {
	priority int
	data     []byte
	err      error
}

type unixgramConn struct {
	c                      *net.UnixConn
	fd                     uintptr
	solicited, unsolicited chan message
}

func Unixgram(ifName string) (Conn, error) {
	var err error
	uc := &unixgramConn{}

	local, err := ioutil.TempFile("/tmp", "wpa_supplicant")
	if err != nil {
		panic(err)
	}
	os.Remove(local.Name())

	uc.c, err = net.DialUnix("unixgram",
		&net.UnixAddr{Name: local.Name(), Net: "unixgram"},
		&net.UnixAddr{Name: path.Join("/run/wpa_supplicant", ifName), Net: "unixgram"})
	if err != nil {
		return nil, err
	}

	file, err := uc.c.File()
	if err != nil {
		return nil, err
	}
	uc.fd = file.Fd()

	uc.solicited = make(chan message)
	uc.unsolicited = make(chan message)

	go uc.readLoop()

	return uc, nil
}

func (uc *unixgramConn) readLoop() {
	for {
		n, _, err := syscall.Recvfrom(int(uc.fd), []byte{}, syscall.MSG_PEEK|syscall.MSG_TRUNC)
		if err != nil {
			continue
		}

		buf := make([]byte, n)
		_, err = uc.c.Read(buf[:])
		if err != nil {
			uc.solicited <- message{
				err: err,
			}
		}

		var p int
		var c chan message
		if len(buf) >= 3 && buf[0] == '<' && buf[2] == '>' {
			switch buf[1] {
			case '0', '1', '2', '3', '4':
				c = uc.unsolicited
				p, _ = strconv.Atoi(string(buf[1]))
				buf = buf[3:]
			default:
				c = uc.solicited
				p = 2
			}
		} else {
			c = uc.solicited
			p = 2
		}

		c <- message{
			priority: p,
			data:     buf,
		}
	}
}

func (uc *unixgramConn) cmd(cmd string) ([]byte, error) {
	// TODO: block if any other commands are running

	_, err := uc.c.Write([]byte(cmd))
	if err != nil {
		return nil, err
	}

	msg := <-uc.solicited
	return msg.data, msg.err
}

func (uc *unixgramConn) Ping() error {
	resp, err := uc.cmd("PING")
	if err != nil {
		return err
	}

	if bytes.Compare(resp, []byte("PONG\n")) == 0 {
		return nil
	}
	return fmt.Errorf("expected %q, got %q", "PONG", resp)
}

func (uc *unixgramConn) ScanResults() ([]ScanResult, error) {
	resp, err := uc.cmd("SCAN_RESULTS")
	if err != nil {
		return nil, err
	}

	s := bufio.NewScanner(bytes.NewBuffer(resp))
	if !s.Scan() {
		return nil, errors.New("failed to parse scan results")
	}
	var bssidCol, freqCol, rssiCol, flagsCol, ssidCol, maxCol int
	for n, col := range strings.Split(s.Text(), " / ") {
		switch col {
		case "bssid":
			bssidCol = n
		case "frequency":
			freqCol = n
		case "signal level":
			rssiCol = n
		case "flags":
			flagsCol = n
		case "ssid":
			ssidCol = n
		}
		maxCol = n
	}

	var res []ScanResult
	for s.Scan() {
		fields := strings.Split(s.Text(), "\t")
		if len(fields) < maxCol {
			continue // TODO: log error
		}

		bssid, err := net.ParseMAC(fields[bssidCol])
		if err != nil {
			continue // TODO: log error
		}

		freq, err := strconv.Atoi(fields[freqCol])
		if err != nil {
			continue // TODO: log error
		}

		rssi, err := strconv.Atoi(fields[rssiCol])
		if err != nil {
			continue // TODO: log error
		}

		var flags []string
		if len(fields[flagsCol]) >= 2 && fields[flagsCol][0] != '[' && fields[flagsCol][len(fields[flagsCol])-1] != ']' {
			flags = strings.Split(fields[flagsCol][1:len(fields[flagsCol])-2], "][")
		}

		res = append(res, &scanResult{
			bssid:     bssid,
			frequency: freq,
			rssi:      rssi,
			flags:     flags,
			ssid:      fields[ssidCol],
		})
	}

	return res, nil
}
