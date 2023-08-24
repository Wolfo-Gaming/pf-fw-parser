interface FirewallLogEntry {
    vhid: string;
    time: Date;
    rulenum: number;
    subrulenum: string;
    anchor: string;
    tracker: number;
    realint: string;
    interface: string;
    reason: string;
    act: string;
    direction: string;
    version: number;
    tos?: string;
    ecn?: string;
    ttl?: number;
    id?: number;
    offset?: number;
    flags?: string;
    protoid?: number;
    proto?: string;
    class?: string;
    flowlabel?: string;
    hlim?: string;
    length?: number;
    srcip?: string;
    dstip?: string;
    srcport?: number;
    dstport?: number;
    src?: string;
    dst?: string;
    datalen?: number;
    tcpflags?: string;
    seq?: number;
    ack?: string;
    window?: number;
    urg?: string;
    options?: string[];
    icmp_type?: string;
    icmp_id?: string;
    icmp_seq?: string;
    icmp_dstip?: string;
    icmp_protoid?: string;
    icmp_port?: string;
    icmp_descr?: string;
    icmp_mtu?: string;
    icmp_otime?: string;
    icmp_rtime?: string;
    icmp_ttime?: string;
    type?: string;
    advskew?: string;
    advbase?: string;
}
export declare function parse_firewall_log_line(line: string, debug?: boolean): FirewallLogEntry | string;
export {};