package gb32960

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/im10furry/gb32960-go-sdk/constant"
)

func makeMinimalPacket(command byte, vin string, data []byte) []byte {
	vinPadded := make([]byte, constant.VINLength)
	for i := range vinPadded {
		vinPadded[i] = 0x20
	}
	copy(vinPadded, []byte(vin))

	totalLen := constant.HeaderSize + len(data) + 1
	pkt := make([]byte, totalLen)
	pos := 0

	pkt[pos] = constant.StartMarker1
	pos++
	pkt[pos] = constant.StartMarker2
	pos++
	pkt[pos] = command
	pos++
	pkt[pos] = 0x01
	pos++
	copy(pkt[pos:pos+constant.VINLength], vinPadded)
	pos += constant.VINLength
	pkt[pos] = constant.EncNone
	pos++
	binary.BigEndian.PutUint16(pkt[pos:pos+2], uint16(len(data)))
	pos += 2
	copy(pkt[pos:pos+len(data)], data)
	pos += len(data)

	var bcc byte
	for i := 2; i < pos; i++ {
		bcc ^= pkt[i]
	}
	pkt[pos] = bcc
	return pkt
}

func TestDecoderSinglePacket(t *testing.T) {
	vin := "TESTVIN1234567890"
	data := []byte{0x01, 0x02, 0x03}
	raw := makeMinimalPacket(constant.CmdHeartbeat, vin, data)

	d := NewDecoder()
	defer d.Close()

	d.Feed(raw)
	pkt, err := d.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if pkt == nil {
		t.Fatal("pkt is nil")
	}

	if pkt.Command != constant.CmdHeartbeat {
		t.Errorf("Command: want %x got %x", constant.CmdHeartbeat, pkt.Command)
	}
	if pkt.VIN != vin {
		t.Errorf("VIN: want %s got %s", vin, pkt.VIN)
	}
	if pkt.EncryptType != constant.EncNone {
		t.Errorf("EncryptType: want %x got %x", constant.EncNone, pkt.EncryptType)
	}
	if pkt.Length != 3 {
		t.Errorf("Length: want 3 got %d", pkt.Length)
	}
}

func TestDecoderTwoPackets(t *testing.T) {
	vin := "TESTVIN1234567890"
	raw1 := makeMinimalPacket(constant.CmdHeartbeat, vin, []byte{0x01, 0x02})
	raw2 := makeMinimalPacket(constant.CmdLogin, vin, []byte{0x03, 0x04, 0x05})
	combined := append(raw1, raw2...)

	d := NewDecoder()
	defer d.Close()
	d.Feed(combined)

	pkt, err := d.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if pkt == nil {
		t.Fatal("first pkt is nil")
	}
	if pkt.Command != constant.CmdHeartbeat {
		t.Errorf("first Command: want %x got %x", constant.CmdHeartbeat, pkt.Command)
	}

	pkt, err = d.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if pkt == nil {
		t.Fatal("second pkt is nil")
	}
	if pkt.Command != constant.CmdLogin {
		t.Errorf("second Command: want %x got %x", constant.CmdLogin, pkt.Command)
	}

	pkt, err = d.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if pkt != nil {
		t.Error("third decode should return nil")
	}
}

func TestDecoderFragmented(t *testing.T) {
	vin := "TESTVIN1234567890"
	data := []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E}
	raw := makeMinimalPacket(constant.CmdRealtime, vin, data)
	splitPoint := len(raw) / 2

	d := NewDecoder()
	defer d.Close()

	d.Feed(raw[:splitPoint])
	pkt, err := d.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if pkt != nil {
		t.Error("should be nil with partial data")
	}

	d.Feed(raw[splitPoint:])
	pkt, err = d.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if pkt == nil {
		t.Fatal("pkt is nil after full data")
	}
	if pkt.Command != constant.CmdRealtime {
		t.Errorf("Command: want %x got %x", constant.CmdRealtime, pkt.Command)
	}
}

func TestDecoderBadChecksumSkip(t *testing.T) {
	vin := "TESTVIN1234567890"
	data := []byte{0x01, 0x02}

	raw := makeMinimalPacket(constant.CmdHeartbeat, vin, data)
	raw[len(raw)-1] ^= 0xFF

	raw2 := makeMinimalPacket(constant.CmdHeartbeat, vin, data)
	combined := append(raw, raw2...)

	d := NewDecoder()
	defer d.Close()
	d.Feed(combined)

	pkt, err := d.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if pkt == nil {
		t.Fatal("pkt is nil")
	}
	if pkt.Command != constant.CmdHeartbeat {
		t.Errorf("Command: want %x got %x", constant.CmdHeartbeat, pkt.Command)
	}
}

func TestEncodeResponse(t *testing.T) {
	vin := "TESTVIN1234567890"
	pkt, err := EncodeResponse(constant.CmdLogin, vin, constant.EncNone, []byte{0x01, 0x02})
	if err != nil {
		t.Fatal(err)
	}
	if pkt[0] != constant.StartMarker1 {
		t.Error("bad start marker 1")
	}
	if pkt[1] != constant.StartMarker2 {
		t.Error("bad start marker 2")
	}
	if pkt[2] != constant.CmdLogin {
		t.Error("bad command")
	}
	if pkt[3] != constant.RespSuccess {
		t.Error("bad response flag")
	}
	if pkt[21] != constant.EncNone {
		t.Error("bad encrypt type")
	}
	if binary.BigEndian.Uint16(pkt[22:24]) != 2 {
		t.Error("bad data length")
	}
}

func TestDecodeLoginData(t *testing.T) {
	data := []byte{
		0x22, 0x01, 0x01, 0x12, 0x00, 0x00,
		0x00, 0x01,
		0x0A,
		'1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
		0x02,
		0x01, 0x01, 0xAA,
		0x02, 0x02, 0xBB, 0xCC,
	}

	loginData, err := DecodeLoginData(data)
	if err != nil {
		t.Fatal(err)
	}
	if loginData.LoginTime.Year() != 2022 {
		t.Errorf("bad year: %d", loginData.LoginTime.Year())
	}
	if loginData.LoginTime.Month() != time.January {
		t.Error("bad month")
	}
	if loginData.LoginTime.Day() != 1 {
		t.Error("bad day")
	}
	if loginData.LoginTime.Hour() != 12 {
		t.Errorf("bad hour: %d", loginData.LoginTime.Hour())
	}
	if loginData.Sequence != 1 {
		t.Error("bad sequence")
	}
	if loginData.ICCID != "1234567890" {
		t.Error("bad ICCID")
	}
	if loginData.ConfigDataCnt != 2 {
		t.Error("bad config count")
	}
	if len(loginData.ConfigData) != 2 {
		t.Error("bad config data len")
	}
}

func TestDecodeLogoutData(t *testing.T) {
	data := []byte{
		0x22, 0x06, 0x15, 0x18, 0x48, 0x00,
		0x00, 0x05,
	}

	logoutData, err := DecodeLogoutData(data)
	if err != nil {
		t.Fatal(err)
	}
	if logoutData.LogoutTime.Year() != 2022 {
		t.Errorf("bad year: %d", logoutData.LogoutTime.Year())
	}
	if logoutData.LogoutTime.Month() != time.June {
		t.Error("bad month")
	}
	if logoutData.LogoutTime.Day() != 15 {
		t.Errorf("bad day: %d", logoutData.LogoutTime.Day())
	}
	if logoutData.LogoutTime.Hour() != 18 {
		t.Errorf("bad hour: %d", logoutData.LogoutTime.Hour())
	}
	if logoutData.LogoutTime.Minute() != 48 {
		t.Errorf("bad minute: %d", logoutData.LogoutTime.Minute())
	}
	if logoutData.Sequence != 5 {
		t.Error("bad sequence")
	}
}

func TestVerifyVIN(t *testing.T) {
	if !VerifyVIN("TESTVIN1234567890") {
		t.Error("valid VIN rejected")
	}
	if VerifyVIN("SHORT") {
		t.Error("short VIN accepted")
	}
	if VerifyVIN("TESTVIN123456789012345") {
		t.Error("long VIN accepted")
	}
	if VerifyVIN("TESTVIN123456789@") {
		t.Error("invalid char VIN accepted")
	}
}

func TestBCDRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		t    time.Time
	}{
		{"2026-01-01 00:00:00", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"2022-06-15 18:48:00", time.Date(2022, 6, 15, 18, 48, 0, 0, time.UTC)},
		{"2025-12-31 23:59:59", time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)},
		{"2000-01-01 00:00:00", time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeBCDTime(tt.t)
			if len(encoded) != 6 {
				t.Fatalf("encoded length: %d", len(encoded))
			}
			decoded := parseBCDTime6(encoded)
			if !decoded.Equal(tt.t) {
				t.Errorf("roundtrip failed: %v != %v", decoded, tt.t)
			}
		})
	}
}

func TestBCDTimeValues(t *testing.T) {
	// 2026-06-15 18:48:30
	ts := time.Date(2026, 6, 15, 18, 48, 30, 0, time.UTC)
	b := encodeBCDTime(ts)

	expected := []byte{0x26, 0x06, 0x15, 0x18, 0x48, 0x30}
	for i, v := range expected {
		if b[i] != v {
			t.Errorf("byte[%d]: want 0x%02X got 0x%02X", i, v, b[i])
		}
	}
}

func TestDecodeLoginDataBinaryMode(t *testing.T) {
	// 旧的二进制编码数据: year=22(0x16), month=1(0x01), day=1(0x01), hour=12(0x0C)
	data := []byte{
		0x16, 0x01, 0x01, 0x0C, 0x00, 0x00,
		0x00, 0x01,
		0x0A,
		'1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
	}

	d := newDecoderWithConfig(TimeCodecBinary, false)
	loginData, err := d.DecodeLoginData(data)
	if err != nil {
		t.Fatal(err)
	}
	if loginData.LoginTime.Year() != 2022 {
		t.Errorf("bad year: %d", loginData.LoginTime.Year())
	}
	if loginData.LoginTime.Hour() != 12 {
		t.Errorf("bad hour: %d", loginData.LoginTime.Hour())
	}
}

func TestBCCIncludeStart(t *testing.T) {
	vin := "TESTVIN1234567890"
	data := []byte{0x01, 0x02}

	// 构造帧，BCC 从 header[0] 开始算（含起始符）
	vinPadded := make([]byte, constant.VINLength)
	for i := range vinPadded {
		vinPadded[i] = 0x20
	}
	copy(vinPadded, []byte(vin))

	totalLen := constant.HeaderSize + len(data) + 1
	pkt := make([]byte, totalLen)
	pkt[0] = constant.StartMarker1
	pkt[1] = constant.StartMarker2
	pkt[2] = constant.CmdHeartbeat
	pkt[3] = 0x01
	copy(pkt[4:21], vinPadded)
	pkt[21] = constant.EncNone
	binary.BigEndian.PutUint16(pkt[22:24], uint16(len(data)))
	copy(pkt[24:], data)

	// BCC 从 position 0 算（含起始符）
	var bccFromStart byte
	for i := 0; i < len(pkt)-1; i++ {
		bccFromStart ^= pkt[i]
	}
	pkt[len(pkt)-1] = bccFromStart

	// 注：0x23 ^ 0x23 = 0x00，所以含起始符的 BCC 与标准 BCC 相同。
	// 两种模式都应接受此帧。
	d1 := newDecoderWithConfig(TimeCodecBCD, false)
	d1.Feed(pkt)
	pkt1, err := d1.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if pkt1 == nil {
		t.Fatal("standard mode should accept packet (BCC is same)")
	}

	d2 := newDecoderWithConfig(TimeCodecBCD, true)
	d2.Feed(pkt)
	pkt2, err := d2.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if pkt2 == nil {
		t.Fatal("bccIncludeStart mode should accept packet")
	}
	if pkt2.Command != constant.CmdHeartbeat {
		t.Errorf("command: want %x got %x", constant.CmdHeartbeat, pkt2.Command)
	}
}

func TestEncodeResponseVINPadding(t *testing.T) {
	vin := "TESTVIN1234567890"
	pkt, err := EncodeResponse(constant.CmdLogin, vin, constant.EncNone, nil)
	if err != nil {
		t.Fatal(err)
	}
	// VIN 区域应全部为 VIN 字符或空格
	vinArea := pkt[4:21]
	for i, b := range vinArea {
		if b == 0x00 {
			t.Errorf("VIN byte[%d] is 0x00 (should be 0x20 for padding)", i)
		}
	}
}
