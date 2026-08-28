package gb32960

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/darkinno-tech/gb32960-go-sdk/constant"
)

var (
	ErrInvalidStart    = errors.New("gb32960: invalid start marker")
	ErrInvalidVIN      = errors.New("gb32960: invalid VIN")
	ErrInvalidLength   = errors.New("gb32960: invalid data length")
	ErrInvalidChecksum = errors.New("gb32960: checksum mismatch")
	ErrBufferTooSmall  = errors.New("gb32960: buffer too small")

	defaultDecoder = &Decoder{timeCodec: TimeCodecBCD}
)

type TimeCodec int

const (
	TimeCodecBCD     TimeCodec = iota // GB/T 32960 标准 BCD 编码
	TimeCodecBinary                   // 二进制编码（兼容非标终端）
)

type Decoder struct {
	buf             []byte
	pos             int
	limit           int
	timeCodec       TimeCodec
	bccIncludeStart bool
}

func NewDecoder() *Decoder {
	return &Decoder{timeCodec: TimeCodecBCD}
}

func newDecoderWithConfig(tc TimeCodec, bccIncludeStart bool) *Decoder {
	return &Decoder{timeCodec: tc, bccIncludeStart: bccIncludeStart}
}

func (d *Decoder) Reset() {
	d.buf = nil
	d.pos = 0
	d.limit = 0
}

func (d *Decoder) Feed(data []byte) {
	if d.buf == nil {
		d.buf = make([]byte, len(data))
		copy(d.buf, data)
		d.pos = 0
		d.limit = len(d.buf)
		return
	}

	remaining := d.limit - d.pos
	if remaining > 0 {
		newBuf := make([]byte, remaining+len(data))
		copy(newBuf, d.buf[d.pos:])
		copy(newBuf[remaining:], data)
		d.buf = newBuf
		d.pos = 0
		d.limit = len(newBuf)
	} else {
		d.buf = make([]byte, len(data))
		copy(d.buf, data)
		d.pos = 0
		d.limit = len(d.buf)
	}
}

func (d *Decoder) Decode() (*Packet, error) {
	for {
		startIdx := d.findStartMarker()
		if startIdx < 0 {
			d.Reset()
			return nil, nil
		}

		d.pos = startIdx

		if d.limit-d.pos < constant.HeaderSize {
			return nil, nil
		}

		header := d.buf[d.pos : d.pos+constant.HeaderSize]
		command := header[2]
		response := header[3]
		vin := string(header[4:21])
		encryptType := header[21]
		dataLength := binary.BigEndian.Uint16(header[22:24])

		d.pos += constant.HeaderSize

		if int(dataLength) > d.limit-d.pos {
			d.pos = startIdx
			return nil, nil
		}

		data := make([]byte, dataLength)
		copy(data, d.buf[d.pos:d.pos+int(dataLength)])
		d.pos += int(dataLength)

		bcc := d.buf[d.pos]
		d.pos++

		if !d.verifyBCC(header, data, bcc) {
			d.pos = startIdx + 2
			continue
		}

		pkt := &Packet{
			Command:     command,
			Response:    response,
			VIN:         vin,
			EncryptType: encryptType,
			Data:        data,
			Length:      dataLength,
		}

		return pkt, nil
	}
}

func (d *Decoder) findStartMarker() int {
	for i := d.pos; i < d.limit-1; i++ {
		if d.buf[i] == constant.StartMarker1 && d.buf[i+1] == constant.StartMarker2 {
			return i
		}
	}
	return -1
}

func calculateBCC(data []byte) byte {
	var bcc byte
	for _, b := range data {
		bcc ^= b
	}
	return bcc
}

func (d *Decoder) verifyBCC(header, data []byte, bcc byte) bool {
	// 标准模式：BCC 从 command 字节开始（不含起始符 0x23 0x23）
	calcBCC := calculateBCC(header[2:])
	for _, b := range data {
		calcBCC ^= b
	}
	if calcBCC == bcc {
		return true
	}
	// 兼容模式：BCC 从起始符开始
	if d.bccIncludeStart {
		calcBCC2 := calculateBCC(header)
		for _, b := range data {
			calcBCC2 ^= b
		}
		if calcBCC2 == bcc {
			return true
		}
	}
	return false
}

func (d *Decoder) Close() {}

// EncodeResponse encodes a GB32960 response frame.
// encryptType specifies the encryption type; if 0, EncNone is used.
// data is the payload body (may be nil for empty responses).
func EncodeResponse(command byte, vin string, encryptType byte, data []byte) ([]byte, error) {
	if len(vin) != constant.VINLength {
		return nil, ErrInvalidVIN
	}
	if encryptType == 0 {
		encryptType = constant.EncNone
	}

	dataLen := len(data)
	totalLen := constant.HeaderSize + dataLen + 1

	pkt := make([]byte, totalLen)
	pos := 0

	pkt[pos] = constant.StartMarker1
	pos++
	pkt[pos] = constant.StartMarker2
	pos++

	pkt[pos] = command
	pos++

	pkt[pos] = constant.RespSuccess
	pos++

	vinPadded := make([]byte, constant.VINLength)
	for i := range vinPadded {
		vinPadded[i] = 0x20
	}
	copy(vinPadded, []byte(vin))
	copy(pkt[pos:pos+constant.VINLength], vinPadded)
	pos += constant.VINLength

	pkt[pos] = encryptType
	pos++

	binary.BigEndian.PutUint16(pkt[pos:pos+2], uint16(dataLen))
	pos += 2

	if dataLen > 0 {
		copy(pkt[pos:pos+dataLen], data)
		pos += dataLen
	}

	bcc := calculateBCC(pkt[2:])
	pkt[pos] = bcc

	return pkt, nil
}

func VerifyVIN(vin string) bool {
	if len(vin) != constant.VINLength {
		return false
	}
	for _, c := range vin {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	return true
}

func DecodeLoginData(data []byte) (*VehicleLoginData, error) {
	return defaultDecoder.DecodeLoginData(data)
}

func (d *Decoder) DecodeLoginData(data []byte) (*VehicleLoginData, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("login data too short: %d bytes", len(data))
	}

	pos := 0
	loginTime := d.decodeTime6(data[pos : pos+6])
	pos += 6
	seq := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2
	iccidLen := int(data[pos])
	pos++

	if pos+iccidLen > len(data) {
		return nil, fmt.Errorf("ICCID length exceeds data: %d > %d", pos+iccidLen, len(data))
	}
	iccid := string(data[pos : pos+iccidLen])
	pos += iccidLen

	var configCnt byte
	var configData []ConfigField
	if pos < len(data) {
		configCnt = data[pos]
		pos++
		for i := byte(0); i < configCnt && pos+2 <= len(data); i++ {
			cf := ConfigField{
				ID:     data[pos],
				Length: data[pos+1],
			}
			pos += 2
			if pos+int(cf.Length) > len(data) {
				break
			}
			cf.Value = make([]byte, cf.Length)
			copy(cf.Value, data[pos:pos+int(cf.Length)])
			pos += int(cf.Length)
			configData = append(configData, cf)
		}
	}

	return &VehicleLoginData{
		LoginTime:     loginTime,
		Sequence:      seq,
		ICCID:         iccid,
		ConfigDataCnt: configCnt,
		ConfigData:    configData,
	}, nil
}

func EncodeLoginResponse(data *LoginResponse) ([]byte, error) {
	pkt := make([]byte, 0, 64)
	pkt = append(pkt, encodeTime6(data.LoginTime)...)
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, data.Sequence)
	pkt = append(pkt, buf...)
	pkt = append(pkt, data.Result)
	pkt = append(pkt, data.Token...)
	return pkt, nil
}

func DecodeLogoutData(data []byte) (*VehicleLogoutData, error) {
	return defaultDecoder.DecodeLogoutData(data)
}

func (d *Decoder) DecodeLogoutData(data []byte) (*VehicleLogoutData, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("logout data too short: %d bytes", len(data))
	}
	return &VehicleLogoutData{
		LogoutTime: d.decodeTime6(data[0:6]),
		Sequence:   binary.BigEndian.Uint16(data[6:8]),
	}, nil
}

func parseTime6(b []byte) time.Time {
	return parseBinaryTime6(b)
}

func parseBinaryTime6(b []byte) time.Time {
	return time.Date(
		2000+int(b[0]), time.Month(b[1]), int(b[2]),
		int(b[3]), int(b[4]), int(b[5]),
		0, time.UTC,
	)
}

func parseBCDTime6(b []byte) time.Time {
	return time.Date(
		2000+int(b[0]>>4)*10+int(b[0]&0x0F),
		time.Month(int(b[1]>>4)*10+int(b[1]&0x0F)),
		int(b[2]>>4)*10+int(b[2]&0x0F),
		int(b[3]>>4)*10+int(b[3]&0x0F),
		int(b[4]>>4)*10+int(b[4]&0x0F),
		int(b[5]>>4)*10+int(b[5]&0x0F),
		0, time.UTC,
	)
}

func (d *Decoder) decodeTime6(b []byte) time.Time {
	if d.timeCodec == TimeCodecBinary {
		return parseBinaryTime6(b)
	}
	return parseBCDTime6(b)
}

func encodeTime6(t time.Time) []byte {
	return encodeBCDTime(t)
}

func encodeBinaryTime6(t time.Time) []byte {
	return []byte{
		byte(t.Year() % 100),
		byte(t.Month()),
		byte(t.Day()),
		byte(t.Hour()),
		byte(t.Minute()),
		byte(t.Second()),
	}
}

func encodeBCDTime(t time.Time) []byte {
	y := t.Year() - 2000
	return []byte{
		byte((y/10)<<4 | (y % 10)),
		byte((int(t.Month())/10)<<4 | (int(t.Month()) % 10)),
		byte((t.Day()/10)<<4 | (t.Day() % 10)),
		byte((t.Hour()/10)<<4 | (t.Hour() % 10)),
		byte((t.Minute()/10)<<4 | (t.Minute() % 10)),
		byte((t.Second()/10)<<4 | (t.Second() % 10)),
	}
}

func binaryPutUint32(buf []byte, v uint32) {
	binary.BigEndian.PutUint32(buf, v)
}

func binaryUint32(buf []byte) uint32 {
	return binary.BigEndian.Uint32(buf)
}

func EncodeParamString(s string) []byte {
	data := []byte(s)
	out := make([]byte, 1+len(data))
	out[0] = byte(len(data))
	copy(out[1:], data)
	return out
}

func decodeParamString(data []byte) (string, int) {
	if len(data) < 1 {
		return "", 0
	}
	length := int(data[0])
	if 1+length > len(data) {
		return "", 0
	}
	return string(data[1 : 1+length]), 1 + length
}

func DecodePlatLoginResponse(data []byte) (*PlatformLoginData, error) {
	return defaultDecoder.DecodePlatLoginResponse(data)
}

func (d *Decoder) DecodePlatLoginResponse(data []byte) (*PlatformLoginData, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("platform login data too short: %d bytes", len(data))
	}
	pos := 0
	loginTime := d.decodeTime6(data[pos : pos+6])
	pos += 6
	seq := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2
	username, n := decodeParamString(data[pos:])
	pos += n
	password, _ := decodeParamString(data[pos:])
	return &PlatformLoginData{
		LoginTime: loginTime,
		Sequence:  seq,
		Username:  username,
		Password:  password,
	}, nil
}

func DecodePlatLogoutResponse(data []byte) (*PlatformLogoutData, error) {
	return defaultDecoder.DecodePlatLogoutResponse(data)
}

func (d *Decoder) DecodePlatLogoutResponse(data []byte) (*PlatformLogoutData, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("platform logout data too short: %d bytes", len(data))
	}
	return &PlatformLogoutData{
		LogoutTime: d.decodeTime6(data[0:6]),
		Sequence:   binary.BigEndian.Uint16(data[6:8]),
	}, nil
}

func DecodeParamQueryData(data []byte) (*ParamQueryData, error) {
	return defaultDecoder.DecodeParamQueryData(data)
}

func (d *Decoder) DecodeParamQueryData(data []byte) (*ParamQueryData, error) {
	if len(data) < 7 {
		return nil, fmt.Errorf("param query data too short: %d bytes", len(data))
	}
	pos := 0
	queryTime := d.decodeTime6(data[pos : pos+6])
	pos += 6
	count := data[pos]
	pos++
	msg := &ParamQueryData{
		QueryTime: queryTime,
		Count:     count,
	}
	for i := byte(0); i < count && pos+4 <= len(data); i++ {
		msg.ParamIDs = append(msg.ParamIDs, binaryUint32(data[pos:pos+4]))
		pos += 4
	}
	return msg, nil
}

func DecodeParamSettingData(data []byte) (*ParamSettingData, error) {
	return defaultDecoder.DecodeParamSettingData(data)
}

func (d *Decoder) DecodeParamSettingData(data []byte) (*ParamSettingData, error) {
	if len(data) < 7 {
		return nil, fmt.Errorf("param setting data too short: %d bytes", len(data))
	}
	pos := 0
	settingTime := d.decodeTime6(data[pos : pos+6])
	pos += 6
	count := data[pos]
	pos++
	msg := &ParamSettingData{
		SettingTime: settingTime,
		Count:       count,
	}
	for i := byte(0); i < count && pos+5 <= len(data); i++ {
		id := binaryUint32(data[pos : pos+4])
		pos += 4
		valLen := int(data[pos])
		pos++
		if pos+valLen > len(data) {
			break
		}
		msg.Params = append(msg.Params, ParamItem{
			ID:    id,
			Value: append([]byte(nil), data[pos:pos+valLen]...),
		})
		pos += valLen
	}
	return msg, nil
}


