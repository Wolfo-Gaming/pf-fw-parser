"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parse_firewall_log_line = void 0;
function convert_real_interface_to_friendly_descr(realint) {
    return realint;
}
function parse_firewall_log_line(line, debug = false) {
    const flent = {};
    let log_split = null;
    if (line.startsWith('<')) {
        // RFC 5424
        const pattern = /^<([0-9]{1,3})>[0-9]*\ (\S+?)\ (\S+?)\ filterlog\ \S+?\ \S+?\ \S+?\ (.*)$/;
        log_split = line.match(pattern);
    }
    else {
        // RFC 3164
        const pattern = /(.*)\s(.*)\sfilterlog\[[0-9]+\]:\s(.*)$/;
        log_split = line.match(pattern);
    }
    if (!log_split) {
        return "";
    }
    const [, time, host, rule] = log_split;
    flent.time = new Date(time.replace('T', ' '));
    const rule_data = rule.split(",");
    let field = 0;
    flent.rulenum = parseInt(rule_data[field++]);
    flent.subrulenum = rule_data[field++];
    flent.anchor = rule_data[field++];
    flent.tracker = parseInt(rule_data[field++]);
    flent.realint = rule_data[field++];
    flent.interface = convert_real_interface_to_friendly_descr(flent.realint);
    flent.reason = rule_data[field++];
    flent.act = rule_data[field++];
    flent.direction = rule_data[field++];
    flent.version = parseInt(rule_data[field++]);
    if (flent.version === 4 || flent.version === 6) {
        if (flent.version === 4) {
            flent.tos = rule_data[field++];
            flent.ecn = rule_data[field++];
            flent.ttl = parseInt(rule_data[field++]);
            flent.id = parseInt(rule_data[field++]);
            flent.offset = parseInt(rule_data[field++]);
            flent.flags = rule_data[field++];
            flent.protoid = parseInt(rule_data[field++]);
            flent.proto = rule_data[field++].toUpperCase();
        }
        else {
            flent.class = rule_data[field++];
            flent.flowlabel = rule_data[field++];
            flent.hlim = rule_data[field++];
            flent.proto = rule_data[field++];
            flent.protoid = parseInt(rule_data[field++]);
        }
        flent.length = parseInt(rule_data[field++]);
        flent.srcip = rule_data[field++];
        flent.dstip = rule_data[field++];
        switch (flent.protoid) {
            case 6:
            case 17: // TCP or UDP
            case 132: // SCTP
                flent.srcport = parseInt(rule_data[field++]);
                flent.dstport = parseInt(rule_data[field++]);
                flent.src = `${flent.srcip}:${flent.srcport}`;
                flent.dst = `${flent.dstip}:${flent.dstport}`;
                flent.datalen = parseInt(rule_data[field++]);
                if (flent.protoid === 6) { // TCP
                    flent.tcpflags = rule_data[field++];
                    flent.seq = parseInt(rule_data[field++]);
                    flent.ack = rule_data[field++];
                    flent.window = parseInt(rule_data[field++]);
                    flent.urg = rule_data[field++];
                    flent.options = rule_data[field++].split(";");
                }
                break;
            case 1:
            case 58: // ICMP (IPv4 & IPv6)
                flent.src = flent.srcip;
                flent.dst = flent.dstip;
                flent.icmp_type = rule_data[field++];
                switch (flent.icmp_type) {
                    case "request":
                    case "reply":
                        flent.icmp_id = rule_data[field++];
                        flent.icmp_seq = rule_data[field++];
                        break;
                    case "unreachproto":
                        flent.icmp_dstip = rule_data[field++];
                        flent.icmp_protoid = rule_data[field++];
                        break;
                    case "unreachport":
                        flent.icmp_dstip = rule_data[field++];
                        flent.icmp_protoid = rule_data[field++];
                        flent.icmp_port = rule_data[field++];
                        break;
                    case "unreach":
                    case "timexceed":
                    case "paramprob":
                    case "redirect":
                    case "maskreply":
                        flent.icmp_descr = rule_data[field++];
                        break;
                    case "needfrag":
                        flent.icmp_dstip = rule_data[field++];
                        flent.icmp_mtu = rule_data[field++];
                        break;
                    case "tstamp":
                        flent.icmp_id = rule_data[field++];
                        flent.icmp_seq = rule_data[field++];
                        break;
                    case "tstampreply":
                        flent.icmp_id = rule_data[field++];
                        flent.icmp_seq = rule_data[field++];
                        flent.icmp_otime = rule_data[field++];
                        flent.icmp_rtime = rule_data[field++];
                        flent.icmp_ttime = rule_data[field++];
                        break;
                    default:
                        flent.icmp_descr = rule_data[field++];
                        break;
                }
                break;
            case 112: // CARP
                flent.type = rule_data[field++];
                flent.ttl = parseInt(rule_data[field++]);
                flent.vhid = rule_data[field++];
                flent.version = parseInt(rule_data[field++]);
                flent.advskew = rule_data[field++];
                flent.advbase = rule_data[field++];
                flent.src = flent.srcip;
                flent.dst = flent.dstip;
                break;
            default:
                flent.src = flent.srcip;
                flent.dst = flent.dstip;
                break;
        }
    }
    else {
        if (debug) {
            throw new Error(`There was an error parsing rule number: ${flent.rulenum}.`);
        }
        return "";
    }
    if (flent.src.trim() !== "" || flent.dst.trim() !== "" || flent.time) {
        return flent;
    }
    else {
        if (debug) {
            throw new Error(`There was an error parsing rule: ${line}.`);
        }
        return "";
    }
}
exports.parse_firewall_log_line = parse_firewall_log_line;
