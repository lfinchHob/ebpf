#include "packet.h"

BPF_HASH(packets);
BPF_HASH(sources);

int packet_counter(struct xdp_md *ctx) {
    u64 counter = 0;
    u64 source_counter = 0;
    u64 key = 0;
    u64 source = 0;
    u64 *p;
    u64 *s;

    key = lookup_protocol(ctx);
    if (key != 0) {
        p = packets.lookup(&key);
        if (p != 0) {
            counter = *p;
        }
        counter++;
        packets.update(&key, &counter);

        source = lookup_source(ctx);
        s = sources.lookup(&source);
        if (s != 0) {
            source_counter = *s;
        }
        source_counter++;
        sources.update(&source, &source_counter);
        
    }

    return XDP_PASS;
}
