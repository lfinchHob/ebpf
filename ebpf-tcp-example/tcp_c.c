struct tcp_probe_t {
    u64 ts;
    u8 saddr[28];
    u8 daddr[28];
    u16 sport;
    u16 dport;
    u16 family;
    u32 mark;
    u16 data_len;
    u32 snd_nxt;
    u32 snd_una;
    u32 snd_cwnd;
    u32 ssthresh;
    u32 snd_wnd;
    u32 srtt;
    u32 rcv_wnd;
    u64 sock_cookie;
};

BPF_HASH(tcp_probe_h, u32, struct tcp_probe_t);


TRACEPOINT_PROBE(tcp, tcp_probe) {
	struct tcp_probe_t val = {0};
	u32 key = bpf_get_prandom_u32();
	val.ts = bpf_ktime_get_ns();
	__builtin_memcpy(val.saddr, args->saddr, 28);
	__builtin_memcpy(val.daddr, args->daddr, 28);
	val.sport = args->sport;
	val.dport = args->dport;
	val.family = args->family;
	val.mark = args->mark;
	val.data_len = args->data_len;
	val.snd_nxt = args->snd_nxt;
	val.snd_una = args->snd_una;
	val.snd_cwnd = args->snd_cwnd;
	val.ssthresh = args->ssthresh;
	val.snd_wnd = args->snd_wnd;
	val.srtt = args->srtt;
	val.rcv_wnd = args->rcv_wnd;
	val.sock_cookie = args->sock_cookie;

	tcp_probe_h.update(&key, &val);
	return 0;
}
