package internal

import (
	"bufio"
	"bytes"
	"io"
	"math/rand"
	"net"
	"strings"
	"time"
)

func splitDurationRandomly(total time.Duration, parts int) []time.Duration {
	if parts <= 1 {
		return []time.Duration{total}
	}
	remain := total
	out := make([]time.Duration, 0, parts)
	for i := 0; i < parts-1; i++ {
		max := remain / time.Duration(parts-i)
		if max <= 0 {
			break
		}
		d := time.Duration(rand.Int63n(int64(max)))
		out = append(out, d)
		remain -= d
	}
	out = append(out, remain)
	return out
}

// 读取客户端版本 返回包裹后的新连接，以便于后续ssh核心模块再次重复读取客户端版本
func readClientVersion(conn net.Conn) (clientVersion string, wrapped net.Conn, err error) {
	reader := bufio.NewReader(conn)
	var consumed bytes.Buffer
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return "", nil, err
	}
	clientVersion = strings.TrimRight(string(line), "\r\n")
	consumed.Write(line)
	replayReader := io.MultiReader(&consumed, conn)
	wrapped = &replayConn{
		Conn:   conn,
		reader: replayReader,
	}
	return clientVersion, wrapped, nil
}

// 延迟发送数据 模拟网络不稳定状态
func connResp(conn net.Conn, data string, delaySeconds int) error {
	data = data + "\r\n"
	if delaySeconds <= 0 {
		_, err := conn.Write([]byte(data))
		return err
	}
	totalDelay := time.Duration(delaySeconds) * time.Second
	start := time.Now()

	maxStalls := len(data)
	stallCount := rand.Intn(maxStalls/2) + 1

	delays := splitDurationRandomly(totalDelay, stallCount)

	delayIdx := 0

	for i := 0; i < len(data); i++ {
		if delayIdx < len(delays) && rand.Intn(2) == 0 {
			time.Sleep(delays[delayIdx])
			delayIdx++
		}

		_, err := conn.Write([]byte{data[i]})
		if err != nil {
			return err
		}

		if delayIdx < len(delays) && rand.Intn(3) == 0 {
			time.Sleep(delays[delayIdx])
			delayIdx++
		}
	}

	elapsed := time.Since(start)
	if remaining := totalDelay - elapsed; remaining > 0 {
		time.Sleep(remaining)
	}
	return nil
}
