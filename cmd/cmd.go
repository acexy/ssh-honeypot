package main

import (
	crand "crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

type Mode int

const (
	ModeSlow Mode = iota
	ModeRealSSH
)

const slowBanner = "SSH-2.0-OpenSSH_7.4p1 Ubuntu-18.04\r\n"

type IPStat struct {
	Count    int
	LastSeen time.Time
}

var (
	stats     = make(map[string]*IPStat)
	mu        sync.Mutex
	sshConfig *ssh.ServerConfig
	connSeq   uint64
)

func init() {
	rand.Seed(time.Now().UnixNano())

	privateKey, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}

	sshConfig = &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			password := string(pass)

			if password == "12345678" {
				log.Printf(
					"FAKE LOGIN SUCCESS user=%s from=%s password=%s",
					c.User(),
					c.RemoteAddr(),
					password,
				)
				return nil, nil
			}
			log.Printf(
				"FAKE LOGIN FAIL user=%s from=%s password=%s",
				c.User(),
				c.RemoteAddr(),
				password,
			)
			return nil, fmt.Errorf("password rejected")
		},
		ServerVersion: "SSH-2.0-OpenSSH_7.4p1",
	}

	sshConfig.AddHostKey(signer)
}

func main() {
	l, err := net.Listen("tcp", ":22")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("listening addr=:22 service=ssh-honeypot")

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("accept error err=%v", err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	ip := conn.RemoteAddr().(*net.TCPAddr).IP.String()
	id := atomic.AddUint64(&connSeq, 1)
	updateStat(ip)

	mode := decideMode(ip)
	mu.Lock()
	stat := stats[ip]
	mu.Unlock()
	log.Printf("conn id=%d ip=%s mode=%v count=%d last_seen=%s", id, ip, mode, stat.Count, stat.LastSeen.Format(time.RFC3339))

	switch mode {
	case ModeSlow:
		handleSlowTarpit(conn, id, ip)
	case ModeRealSSH:
		handleFakeSSH(conn, id, ip)
	default:
		conn.Close()
	}
}

func updateStat(ip string) {
	mu.Lock()
	defer mu.Unlock()

	stat := stats[ip]
	if stat == nil {
		stat = &IPStat{}
		stats[ip] = stat
	}
	stat.Count++
	stat.LastSeen = time.Now()
}

func decideMode(ip string) Mode {
	r := rand.Intn(100)

	mu.Lock()
	stat := stats[ip]
	mu.Unlock()

	if stat != nil && stat.Count >= 5 {
		if r < 70 {
			return ModeRealSSH
		}
		return ModeSlow
	}

	if r < 90 {
		return ModeSlow
	}
	return ModeRealSSH
}

func randDuration(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(rand.Int63n(int64(max-min)))
}

func handleSlowTarpit(conn net.Conn, id uint64, ip string) {
	defer conn.Close()

	perByteDelay := randDuration(100*time.Millisecond, 1500*time.Millisecond)
	bytesToSend := rand.Intn(len(slowBanner)-1) + 1
	finalHold := randDuration(5*time.Second, 3*time.Minute)
	log.Printf("slow start id=%d ip=%s bytes=%d per_byte_delay=%s final_hold=%s", id, ip, bytesToSend, perByteDelay, finalHold)

	for i := 0; i < bytesToSend; i++ {
		if _, err := conn.Write([]byte{slowBanner[i]}); err != nil {
			log.Printf("slow write error id=%d ip=%s err=%v", id, ip, err)
			return
		}
		time.Sleep(perByteDelay)
	}

	time.Sleep(finalHold)
	log.Printf("slow close id=%d ip=%s", id, ip)
}

func handleFakeSSH(conn net.Conn, id uint64, ip string) {
	defer conn.Close()
	log.Printf("fakeSSH start id=%d ip=%s", id, ip)
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
	if err != nil {
		return
	}

	log.Printf("fakeSSH start id=%d ip=%s SSH authentication success from %s", id, ip, sshConn.RemoteAddr())

	go ssh.DiscardRequests(reqs)

	for ch := range chans {
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}

		channel, requests, err := ch.Accept()
		if err != nil {
			return
		}

		// 处理 session 内请求
		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "shell", "pty-req", "exec":
					req.Reply(true, nil)
				default:
					req.Reply(false, nil)
				}
			}
		}(requests)
		channel.Write([]byte("Last login: Tue Sep 17 02:31:42 UTC 2024\n"))
		channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
		time.Sleep(300 * time.Millisecond)
		channel.Close()
	}

	time.Sleep(200 * time.Millisecond)
}
