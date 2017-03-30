package syz_structs

import (
	"strings"
	"strconv"
	"regexp"
	"fmt"
)

type Stack []byte

func (s Stack) Push(c byte) Stack {
	return append(s, c)
}

func (s Stack) Pop() (Stack, byte) {
	l := len(s)
	if l == 0 {
		panic("popping an empty stack")
	}
	r := s[l-1]
	s = s[:l-1]
	return s, r
}

type Pair struct {
	A string
	B string
}

var (
	Unsupported = map[string]bool{
		"brk": true,
		//"fstat": true,
		//"exit_group": true,
		"mprotect": true,
		"munmap": true,
		"": true,
		"execve": true,
		"access": true,
		"mmap": true,
		//"accept": true, // need to determine accept type from the type of sockfd. Unsure how to do this cleanly.
		//"bind": true, // same issue
		//"sendto": true, // same
		// also: problem with select, 2nd arg not correct format
		//"select": true,
		//"recvfrom": true,
		//"socket": true, // ltp_asapi_03 has comment in format!!
		"sendmsg": true,
		"recvmsg": true,
		"gettimeofday": true,
		"keyctl": true,
		"shmctl": true,
		"getsockname": true,
		//"connect": true,
		"getsockopt": true,
		//"accept4": true,
		"mremap": true, // knowing vma location is difficult
		"getcwd": true, // unsupported
		"setdomainname": true, // unsupported
		"reboot": true, // unsupported
		"getppid": true, // unsupported
		"umask": true, // unsupported
		"adjtimex": true, // unsupported
		"ioctl$FIONBIO": true, // unsupported
		"sysfs": true,
		"chdir": true,
		//"fcntl": true,
		//"arch_prctl": true, // has two conflicting method signatures!! http://man7.org/linux/man-pages/man2/arch_prctl.2.html
		//"rt_sigaction": true, // constants such as SIGRTMIN are not defined in syzkaller, and missing last void __user *, restorer argument
		//"rt_sigprocmask": true, // second arg given as an array, should be pointer
		//"getrlimit": true, // has arg 8192*1024, cannot evaluate easily
		//"statfs": true, // types disagree, strace gives struct, syzkaller expects buffer
		//"fstatfs": true, // types disagree, strace gives struct, syzkaller expects buffer
		//"ioctl": true, // types disagree, strace gives struct, syzkaller expects buffer
		/* can build the ioctl$arg from the 2nd arg */
		//"getdents": true, // types disagree, strace gives struct, syzkaller expects buffer
	}

	Accept_labels = map[string]string {
		"fd": "", // TODO: this is an illegal value. how do we interpret the uniontype?
		"sock": "",
		"sock_alg": "$alg",
		"sock_in": "$inet",
		"sock_in6": "$inet6",
		"sock_netrom": "$netrom",
		"sock_nfc_llcp": "$nfc_llcp",
		"sock_sctp": "$sctp",
		"sock_unix": "$unix",
	}

	Bind_labels = map[string]string {
		"fd": "",
		"sock": "",
		"sock_alg": "$alg",
		"sock_bt_hci": "$bt_hci",
		"sock_bt_l2cap": "$bt_l2cap",
		"sock_bt_rfcomm": "$bt_rfcomm",
		"sock_bt_sco": "$bt_sco",
		"sock_in": "$inet",
		"sock_in6": "$inet6",
		"sock_netlink": "$netlink",
		"sock_netrom": "$netrom",
		"sock_nfc_llcp": "$nfc_llcp",
		"sock_sctp": "$sctp",
		"sock_unix": "$unix",
	}

	Connect_labels = map[string]string {
		"fd": "",
		"sock": "",
		"sock_bt_l2cap": "$bt_l2cap",
		"sock_bt_rfcomm": "$bt_rfcomm",
		"sock_bt_sco": "$bt_sco",
		"sock_in": "$inet",
		"sock_in6": "$inet6",
		"sock_netlink": "$netlink",
		"sock_netrom": "$netrom",
		"sock_nfc_llcp": "$nfc_llcp",
		"sock_nfc_raw": "$nfc_raw",
		"sock_sctp": "$sctp",
		"sock_unix": "$unix",
	}

	Setsockopt_labels = map[Pair]string {
		Pair{"SOL_SOCKET","SO_DETACH_FILTER"}: "$sock_void",
		Pair{"SOL_SOCKET","SO_MARK"}: "$sock_void",
		Pair{"SOL_SOCKET","SO_ACCEPTCONN"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_BROADCAST"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_DEBUG"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_DOMAIN"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_ERROR"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_DONTROUTE"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_KEEPALIVE"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_PEEK_OFF"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_PRIORITY"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_PROTOCOL"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_RCVBUF"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_RCVBUFFORCE"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_RCVLOWAT"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_SNDLOWAT"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_REUSEADDR"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_SNDBUF"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_SNDBUFFORCE"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_TIMESTAMP"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_TYPE"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_REUSEPORT"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_OOBINLINE"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_NO_CHECK"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_PASSCRED"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_TIMESTAMPNS"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_LOCK_FILTER"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_PASSSEC"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_RXQ_OVFL"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_WIFI_STATUS"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_NOFCS"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_SELECT_ERR_QUEUE"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_BUSY_POLL"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_MAX_PACING_RAT"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_BINDTODEVICE"}: "$sock_str",
		Pair{"SOL_SOCKET","SO_LINGER"}: "$sock_linger",
		Pair{"SOL_SOCKET","SO_PEERCRED"}: "$sock_cred",
		Pair{"SOL_SOCKET","SO_RCVTIMEO"}: "$sock_timeval",
		Pair{"SOL_SOCKET","SO_SNDTIMEO"}: "$sock_timeval",
		Pair{"SOL_SOCKET","SO_ATTACH_BPF"}: "$sock_attack_bpf",
		Pair{"SOL_SOCKET","SO_TIMESTAMPING"}: "$SO_TIMESTAMPING",
		Pair{"SOL_SOCKET","SO_ATTACH_FILTER"}: "$SO_ATTACH_FILTER",
		Pair{"IPPROTO_IPV6", "IPV6_RECVPKTINFO"}: "$ip6_int",
		Pair{"IPPROTO_IPV6", "IPV6_RECVHOPLIMIT"}: "$ip6_int",
		Pair{"IPPROTO_IPV6", "IPV6_RECVRTHDR"}: "$ip6_int",
		Pair{"IPPROTO_IPV6", "IPV6_RECVHOPOPTS"}: "$ip6_int",
		Pair{"IPPROTO_IPV6", "IPV6_RECVDSTOPTS"}: "$ip6_int",
		Pair{"IPPROTO_IPV6", "IPV6_RECVTCLASS"}: "$ip6_int",
		Pair{"IPPROTO_IPV6", "IPV6_2292HOPOPTS"}: "$ip6_int",
		Pair{"IPPROTO_IPV6", "IPV6_2292HOPLIMIT"}: "$ip6_int",
		Pair{"IPPROTO_IPV6", "IPV6_2292RTHDR"}: "$ip6_int",
		Pair{"IPPROTO_IPV6", "IPV6_2292DSTOPTS"}: "$ip6_int",
		Pair{"IPPROTO_IPV6", "IPV6_2292PKTINFO"}: "$ip6_int",
	}

	Getsockopt_labels = map[Pair]string {
		Pair{"SOL_SOCKET","SO_ACCEPTCONN"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_BROADCAST"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_DEBUG"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_DOMAIN"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_ERROR"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_DONTROUTE"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_KEEPALIVE"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_PEEK_OFF"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_PRIORITY"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_PROTOCOL"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_RCVBUF"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_RCVBUFFORCE"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_RCVLOWAT"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_SNDLOWAT"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_REUSEADDR"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_SNDBUF"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_SNDBUFFORCE"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_TIMESTAMP"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_TYPE"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_REUSEPORT"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_OOBINLINE"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_NO_CHECK"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_PASSCRED"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_TIMESTAMPNS"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_LOCK_FILTER"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_PASSSEC"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_RXQ_OVFL"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_WIFI_STATUS"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_NOFCS"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_SELECT_ERR_QUEUE"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_BUSY_POLL"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_MAX_PACING_RAT"}: "$sock_int",
		Pair{"SOL_SOCKET","SO_LINGER"}: "$sock_linger",
		Pair{"SOL_SOCKET","SO_PEERCRED"}: "$sock_cred",
		Pair{"SOL_SOCKET","SO_RCVTIMEO"}: "$sock_timeval",
		Pair{"SOL_SOCKET","SO_SNDTIMEO"}: "$sock_timeval",
		Pair{"SOL_SOCKET","SO_TIMESTAMPING"}: "$SO_TIMESTAMPING",
		Pair{"SOL_SOCKET","SO_BINDTODEVICE"}: "$sock_buf",
		Pair{"SOL_SOCKET","SO_PEERNAME"}: "$sock_buf",
		Pair{"SOL_SOCKET","SO_PEERSEC"}: "$sock_buf",
		Pair{"SOL_SOCKET","SO_GET_FILTE"}: "$sock_buf",
	}

	SocketLevel_map = map[string]string {
		"SOL_SOCKET": "SOL_SOCKET",
		"SOL_IPV6": "IPPROTO_IPV6",
		"SOL_ICMPV6": "IPPROTO_ICMP",
	}

	Sendto_labels = map[string]string {
		"fd": "",
		"sock": "",
		"sock_in": "$inet",
		"sock_in6": "$inet6",
		"sock_sctp": "$sctp",
		"sock_unix": "$unix",
	}

	Recvfrom_labels = map[string]string {
		"fd": "",
		"sock": "",
		"sock_in": "$inet",
		"sock_in6": "$inet6",
		"sock_sctp": "$sctp",
		"sock_unix": "$unix",
	}

	Ioctl_map = map[string]string {
		"FIONBIO": "int_in",
		"FIOASYNC": "int_in",
	}

	Socket_labels = map[string]string {
		"AF_INET": "$inet",
		"AF_INET6": "$inet6",
		"AF_KCM": "$kcm",
		"AF_UNIX": "$unix",
	}

	Fcntl_labels = map[string]string {
		"F_DUPFD": "$dupfd",
		"F_DUPFD_CLOEXEC": "$dupfd",
		"F_GETFD": "$getflags",
		"F_GETFL": "$getflags",
		"F_GETSIG": "$getflags",
		"F_GETLEASE": "$getflags",
		"F_GETPIPE_SZ": "$getflags",
		"F_GET_SEALS": "$getflags",
		"F_SETFD": "$setflags",
		"F_SETFL": "$setstatus",
		"F_SETLK": "$lock",
		"F_SETLKW": "$lock",
		"F_GETLK": "$lock",
		"F_GETOWN": "$getown",
		"F_SETOWN": "$setown",
		"F_GETOWN_EX": "$getownex",
		"F_SETOWN_EX": "$setownex",
		"F_SETSIG": "$setsig",
		"F_SETLEASE": "$setlease",
		"DN_MULTISHOT": "$notify",
		"DN_ACCESS": "$notify",
		"DN_MODIFY": "$notify",
		"DN_CREATE": "$notify",
		"DN_DELETE": "$notify",
		"DN_RENAME": "$notify",
		"DN_ATTRIB": "$notify",
		"F_SETPIPE_SZ": "$setpipe",
		"F_ADD_SEALS": "$addseals",
	}

	Macros = []string{"makedev"}

	MacroExpand_map = map[string]func(string)string {
		"makedev": MakeDev,
	}
)

func Inet_addr(ipaddr string) uint32 {
	var (
		ip                 = strings.Split(ipaddr, ".")
		ip1, ip2, ip3, ip4 uint64
		ret                uint32
	)
	ip1, _ = strconv.ParseUint(ip[0], 10, 8)
	ip2, _ = strconv.ParseUint(ip[1], 10, 8)
	ip3, _ = strconv.ParseUint(ip[2], 10, 8)
	ip4, _ = strconv.ParseUint(ip[3], 10, 8)
	ret = uint32(ip4)<<24 + uint32(ip3)<<16 + uint32(ip2)<<8 + uint32(ip1)
	return ret
}

func Htons(port uint16) uint16 {
	var (
		lowbyte  uint8  = uint8(port)
		highbyte uint8  = uint8(port >> 8)
		ret      uint16 = uint16(lowbyte)<<8 + uint16(highbyte)
	)
	return ret
}


func Htonl(port uint32) uint32 {
	var (
		byte1  uint8  = uint8(port)
		byte2  uint8  = uint8(port >> 8)
		byte3  uint8  = uint8(port >> 16)
		byte4  uint8  = uint8(port >> 24)
		ret    uint32 = uint32(byte1)<<24 + uint32(byte2)<<16 + uint32(byte3)<<8 + uint32(byte4)
	)
	return ret
}




func MakeDev(macro string) string {
	var major, minor, id int64
	var err error
	deviceIds := regexp.MustCompile("[0-9]+").FindAllString(macro, 2) //mknod should only have 2 values
	fmt.Printf("device Ids: %v\n", deviceIds)
	if len(deviceIds) != 2 {
		return macro
	}

	if major, err = strconv.ParseInt(deviceIds[0], 0, 64); err != nil {
		return macro
	}

	if minor, err = strconv.ParseInt(deviceIds[1], 0, 64); err != nil {
		return macro
	}

	id = ((minor & 0xff) | ((major & 0xfff) << 8) |  ((minor & ^0xff) << 12) | ((major & ^0xfff) << 32))

	fmt.Printf("id: %d\n", id)
	return strconv.FormatInt(id, 10)
}


